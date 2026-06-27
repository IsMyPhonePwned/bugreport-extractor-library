//! Map Android Linux UIDs to package names using [`ParserType::Package`] output.

use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use crate::parsers::ParserType;

/// Android multi-user UID range (user N app → N * 100_000 + appId).
pub const PER_USER_RANGE: u32 = 100_000;

/// Build `full_linux_uid → package_name` from package parser JSON.
pub fn build_uid_package_map(package_output: &Value) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Some(sections) = package_output.as_array() else {
        return map;
    };

    for section in sections {
        let Some(packages) = section.get("packages").and_then(|v| v.as_array()) else {
            continue;
        };
        for pkg in packages {
            let Some(name) = pkg
                .get("package_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            else {
                continue;
            };

            if let Some(uid) = pkg.get("uid").and_then(value_as_u32) {
                map.entry(uid).or_insert_with(|| name.to_string());
            }

            let app_id = pkg
                .get("appId")
                .and_then(value_as_u32)
                .or_else(|| pkg.get("app_id").and_then(value_as_u32));

            if let Some(app_id) = app_id {
                map.entry(app_id).or_insert_with(|| name.to_string());
                if let Some(users) = pkg.get("users").and_then(|v| v.as_array()) {
                    for user in users {
                        if let Some(user_id) = user.get("user_id").and_then(value_as_u32) {
                            let full_uid = user_id
                                .checked_mul(PER_USER_RANGE)
                                .and_then(|base| base.checked_add(app_id));
                            if let Some(full_uid) = full_uid {
                                map.entry(full_uid)
                                    .or_insert_with(|| name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

fn value_as_u32(v: &Value) -> Option<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| v.as_i64().and_then(|n| u32::try_from(n).ok()))
}

/// Resolve a Linux UID to a package name.
pub fn lookup_package(uid_map: &HashMap<u32, String>, uid: u32) -> Option<&str> {
    uid_map.get(&uid).map(String::as_str)
}

/// Add `package_name` to each socket when `uid` is known in the map.
pub fn enrich_network_sockets(network: &mut Value, uid_map: &HashMap<u32, String>) {
    let Some(sockets) = network
        .as_object_mut()
        .and_then(|o| o.get_mut("sockets"))
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };

    for sock in sockets {
        let Some(obj) = sock.as_object_mut() else {
            continue;
        };
        attach_package_name(obj, uid_map);
    }
}

/// Add `package_name` to logcat events when `uid` is present.
pub fn enrich_logcat_events(logcat: &mut Value, uid_map: &HashMap<u32, String>) {
    let Some(events) = logcat
        .as_object_mut()
        .and_then(|o| o.get_mut("events"))
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };

    for event in events {
        let Some(obj) = event.as_object_mut() else {
            continue;
        };
        attach_package_name(obj, uid_map);
    }
}

fn attach_package_name(obj: &mut Map<String, Value>, uid_map: &HashMap<u32, String>) {
    if obj.contains_key("package_name") {
        return;
    }
    let Some(uid) = obj.get("uid").and_then(value_as_u32) else {
        return;
    };
    if let Some(pkg) = lookup_package(uid_map, uid) {
        obj.insert("package_name".to_string(), json!(pkg));
    }
}

/// After concurrent parsing, enrich network/logcat JSON using package UID map when available.
pub fn enrich_parser_results(
    results: &mut [(
        ParserType,
        Result<Value, Box<dyn Error + Send + Sync>>,
        Duration,
    )],
) {
    let uid_map = results
        .iter()
        .find(|(pt, _, _)| *pt == ParserType::Package)
        .and_then(|(_, res, _)| res.as_ref().ok())
        .map(build_uid_package_map)
        .unwrap_or_default();

    if uid_map.is_empty() {
        return;
    }

    for (pt, res, _) in results.iter_mut() {
        if let Ok(v) = res {
            match pt {
                ParserType::Network => enrich_network_sockets(v, &uid_map),
                ParserType::Logcat => enrich_logcat_events(v, &uid_map),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_map_user0_and_multi_user() {
        let packages = json!([{
            "packages": [{
                "package_name": "com.example.app",
                "appId": 10333,
                "users": [
                    {"user_id": 0},
                    {"user_id": 10}
                ]
            }]
        }]);
        let map = build_uid_package_map(&packages);
        assert_eq!(map.get(&10333).map(String::as_str), Some("com.example.app"));
        assert_eq!(
            map.get(&1_010_333).map(String::as_str),
            Some("com.example.app")
        );
    }

    #[test]
    fn enrich_network_socket_adds_package_name() {
        let mut network = json!({
            "sockets": [{"uid": 10333, "protocol": "tcp"}]
        });
        let mut map = HashMap::new();
        map.insert(10333, "com.example.app".to_string());
        enrich_network_sockets(&mut network, &map);
        assert_eq!(
            network["sockets"][0]["package_name"],
            "com.example.app"
        );
    }
}
