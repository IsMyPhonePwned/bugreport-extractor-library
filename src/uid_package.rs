//! Map Android Linux UIDs to package names and process identities using parser output.

use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use crate::parsers::ParserType;

/// Android multi-user UID range (user N app → N * 100_000 + appId).
pub const PER_USER_RANGE: u32 = 100_000;

const AID_APP_START: u32 = 10_000;
const FIRST_ISOLATED_UID: u32 = 99_000;

/// Process identity resolved from [`ParserType::Process`] output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub cmd: String,
    pub user: String,
}

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
                if is_app_linux_uid(uid) && !package_uses_shared_uid(pkg) {
                    map.entry(uid).or_insert_with(|| name.to_string());
                }
            }

            let app_id = pkg
                .get("appId")
                .and_then(value_as_u32)
                .or_else(|| pkg.get("app_id").and_then(value_as_u32));

            if let Some(app_id) = app_id {
                if is_app_linux_uid(app_id) && !package_uses_shared_uid(pkg) {
                    map.entry(app_id).or_insert_with(|| name.to_string());
                }
                if let Some(users) = pkg.get("users").and_then(|v| v.as_array()) {
                    for user in users {
                        if let Some(user_id) = user.get("user_id").and_then(value_as_u32) {
                            let full_uid = user_id
                                .checked_mul(PER_USER_RANGE)
                                .and_then(|base| base.checked_add(app_id));
                            if let Some(full_uid) = full_uid {
                                if is_app_linux_uid(full_uid) {
                                    map.entry(full_uid)
                                        .or_insert_with(|| name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

/// Build `linux_uid → process` from process parser JSON (`ps` / `top` user column).
pub fn build_uid_process_map(process_output: &Value) -> HashMap<u32, ProcessIdentity> {
    let mut by_uid: HashMap<u32, Vec<ProcessIdentity>> = HashMap::new();
    let Some(processes) = process_output.as_array() else {
        return HashMap::new();
    };

    for proc in processes {
        let Some(pid) = proc.get("pid").and_then(value_as_u32) else {
            continue;
        };
        let user = proc
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let cmd = proc
            .get("cmd")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(uid) = parse_android_user_uid(user) else {
            continue;
        };
        if uid == 0 {
            continue;
        }
        by_uid
            .entry(uid)
            .or_default()
            .push(ProcessIdentity {
                pid,
                cmd: cmd.to_string(),
                user: user.to_string(),
            });
    }

    by_uid
        .into_iter()
        .map(|(uid, procs)| (uid, pick_representative_process(procs)))
        .collect()
}

/// Parse an Android `ps` user column (`u0_a109`, `system`, …) into a Linux UID.
pub fn parse_android_user_uid(user: &str) -> Option<u32> {
    if let Some(rest) = user.strip_prefix('u') {
        let (user_id_str, suffix) = rest.split_once('_')?;
        let user_id: u32 = user_id_str.parse().ok()?;
        let base = user_id.checked_mul(PER_USER_RANGE)?;

        if let Some(offset) = suffix.strip_prefix('a').and_then(|s| s.parse::<u32>().ok()) {
            return base.checked_add(AID_APP_START.checked_add(offset)?);
        }
        if let Some(offset) = suffix.strip_prefix('i').and_then(|s| s.parse::<u32>().ok()) {
            return base.checked_add(FIRST_ISOLATED_UID.checked_add(offset)?);
        }
        if let Some(app_id) = named_android_app_id(suffix) {
            return base.checked_add(app_id);
        }
        return None;
    }

    named_android_app_id(user)
}

fn named_android_app_id(name: &str) -> Option<u32> {
    match name {
        "root" => Some(0),
        "system" => Some(1000),
        "radio" | "phone" => Some(1001),
        "bluetooth" => Some(1002),
        "graphics" => Some(1003),
        "input" => Some(1004),
        "audio" => Some(1005),
        "camera" => Some(1006),
        "log" => Some(1007),
        "compass" => Some(1008),
        "mount" => Some(1009),
        "wifi" => Some(1010),
        "adb" => Some(1011),
        "install" => Some(1012),
        "media" => Some(1013),
        "dhcp" => Some(1014),
        "sdcard_rw" => Some(1015),
        "vpn" => Some(1016),
        "keystore" => Some(1017),
        "nfc" => Some(1027),
        "clat" => Some(1029),
        "media_rw" => Some(1023),
        "drm" => Some(1019),
        "shell" => Some(2000),
        "nobody" => Some(9999),
        _ => None,
    }
}

fn pick_representative_process(mut procs: Vec<ProcessIdentity>) -> ProcessIdentity {
    if let Some(idx) = procs
        .iter()
        .position(|p| p.cmd.contains('.') && !p.cmd.contains(' '))
    {
        return procs.remove(idx);
    }
    procs.sort_by_key(|p| p.pid);
    procs.into_iter().next().expect("non-empty process list")
}

fn value_as_u32(v: &Value) -> Option<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| v.as_i64().and_then(|n| u32::try_from(n).ok()))
}

/// Linux UIDs below this are system/shared (e.g. `android.uid.system/1000`), not per-app IDs.
pub fn is_app_linux_uid(uid: u32) -> bool {
    uid >= AID_APP_START
}

fn package_uses_shared_uid(pkg: &Value) -> bool {
    pkg.get("sharedUser")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.contains("SharedUserSetting") || s.contains("android.uid."))
}

/// Resolve a Linux UID to a package name.
pub fn lookup_package(uid_map: &HashMap<u32, String>, uid: u32) -> Option<&str> {
    if !is_app_linux_uid(uid) {
        return None;
    }
    uid_map.get(&uid).map(String::as_str)
}

/// Resolve a Linux UID to a process identity.
pub fn lookup_process(
    process_map: &HashMap<u32, ProcessIdentity>,
    uid: u32,
) -> Option<&ProcessIdentity> {
    if uid == 0 {
        return None;
    }
    process_map.get(&uid)
}

/// Add `package_name` or process fields to each socket when resolvable.
pub fn enrich_network_sockets(
    network: &mut Value,
    uid_map: &HashMap<u32, String>,
    process_map: &HashMap<u32, ProcessIdentity>,
) {
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
        attach_socket_identity(obj, uid_map, process_map);
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

fn attach_socket_identity(
    obj: &mut Map<String, Value>,
    uid_map: &HashMap<u32, String>,
    process_map: &HashMap<u32, ProcessIdentity>,
) {
    if is_stale_unattributed_socket(obj) {
        obj.remove("package_name");
        obj.remove("process_cmd");
        obj.remove("process_pid");
        obj.remove("process_user");
        obj.insert("attribution_status".to_string(), json!("stale_socket"));
        obj.insert(
            "owner".to_string(),
            json!("unattributed (stale socket)"),
        );
        obj.insert("owner_type".to_string(), json!("stale"));
    } else {
        let netstat_program = obj
            .get("program_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let netstat_pid = obj.get("program_pid").and_then(value_as_u32);

        if let Some(program) = netstat_program {
            // Netstat PID/Program is per-socket and overrides UID-based guesses.
            obj.remove("package_name");
            obj.remove("process_cmd");
            obj.remove("process_pid");
            if looks_like_package_name(&program) {
                obj.insert("package_name".to_string(), json!(program));
            } else {
                obj.insert("process_cmd".to_string(), json!(program));
                if let Some(pid) = netstat_pid {
                    obj.insert("process_pid".to_string(), json!(pid));
                }
            }
        } else if !obj.contains_key("package_name") {
            attach_package_name(obj, uid_map);
            if !obj.contains_key("package_name") {
                attach_process_identity(obj, process_map);
            }
        }
    }

    annotate_listener_socket(obj);
    annotate_peer_ip(obj);
    attach_owner_fields(obj);
}

fn is_terminal_tcp_state(state: &str) -> bool {
    let compact: String = state
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect();
    matches!(
        compact.as_str(),
        "LASTACK" | "FINWAIT1" | "FINWAIT2" | "TIMEWAIT" | "CLOSEWAIT" | "CLOSING" | "CLOSE"
    )
}

/// Set `peer_ip` for outbound sockets (UI should group on this, not wildcard remotes).
fn annotate_peer_ip(obj: &mut Map<String, Value>) {
    if obj.get("socket_direction").and_then(|v| v.as_str()) == Some("listen") {
        return;
    }
    if obj.contains_key("peer_ip") && !obj.get("peer_ip").map(|v| v.is_null()).unwrap_or(false) {
        return;
    }
    if let Some(v4) = obj.get("remote_ipv4").and_then(|v| v.as_str()) {
        obj.insert("peer_ip".to_string(), json!(v4));
        return;
    }
    if let Some(ip) = obj.get("remote_ip").and_then(|v| v.as_str()) {
        if !is_wildcard_ip(ip) {
            obj.insert("peer_ip".to_string(), json!(ip));
        }
    }
}

fn is_wildcard_ip(ip: &str) -> bool {
    matches!(ip, "" | "*" | "::" | "0.0.0.0" | "0:0:0:0:0:0:0:0")
}

/// Listening sockets use `::` / `0.0.0.0` as remote — not a real peer IP.
fn annotate_listener_socket(obj: &mut Map<String, Value>) {
    let remote_ip = obj
        .get("remote_ip")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let remote_role = obj
        .get("remote_ip_role")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let is_listen_state = socket_state_normalized(obj).contains("LISTEN");
    let listener = is_listen_state
        || remote_role == "any"
        || is_wildcard_ip(remote_ip)
        || obj
            .get("remote_address")
            .and_then(|v| v.as_str())
            .is_some_and(|a| a.ends_with(":*") || a.contains("[::]:*"));

    if !listener {
        return;
    }

    obj.insert("socket_direction".to_string(), json!("listen"));
    obj.insert("peer_ip".to_string(), Value::Null);
    obj.insert("peer_ip_display".to_string(), json!("(any)"));
    if obj
        .get("attribution_status")
        .and_then(|v| v.as_str())
        .is_none()
    {
        obj.insert("attribution_status".to_string(), json!("listener"));
    }
}

fn socket_state_normalized(obj: &Map<String, Value>) -> String {
    obj.get("state")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_uppercase()
        .replace('-', "_")
}

/// Sockets in terminal TCP states with uid/inode 0 carry no owning app in bugreports.
pub fn is_stale_unattributed_socket(obj: &Map<String, Value>) -> bool {
    if obj
        .get("program_name")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty() && s != "-")
    {
        return false;
    }

    let uid = obj.get("uid").and_then(value_as_u32);
    let inode = obj.get("inode").and_then(|v| v.as_u64());
    let uid_unowned = uid.is_none() || uid == Some(0);
    let inode_unowned = inode.is_none() || inode == Some(0);
    if !(uid_unowned && inode_unowned) {
        return false;
    }

    matches!(
        socket_state_normalized(obj).as_str(),
        "LAST_ACK"
            | "FIN_WAIT1"
            | "FIN_WAIT_1"
            | "FIN_WAIT2"
            | "FIN_WAIT_2"
            | "TIME_WAIT"
            | "CLOSE_WAIT"
            | "CLOSING"
            | "CLOSE"
    ) || obj
        .get("state")
        .and_then(|v| v.as_str())
        .is_some_and(is_terminal_tcp_state)
}

fn looks_like_package_name(name: &str) -> bool {
    name.contains('.') && !name.starts_with("binder:") && !name.contains(' ')
}

fn attach_process_identity(obj: &mut Map<String, Value>, process_map: &HashMap<u32, ProcessIdentity>) {
    if obj.contains_key("process_cmd") || process_map.is_empty() {
        return;
    }
    let Some(uid) = obj.get("uid").and_then(value_as_u32) else {
        return;
    };
    if let Some(proc) = lookup_process(process_map, uid) {
        obj.insert("process_cmd".to_string(), json!(proc.cmd));
        obj.insert("process_pid".to_string(), json!(proc.pid));
        if !proc.user.is_empty() {
            obj.insert("process_user".to_string(), json!(proc.user));
        }
    }
}

fn attach_owner_fields(obj: &mut Map<String, Value>) {
    if obj
        .get("attribution_status")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "stale_socket")
    {
        return;
    }
    if let Some(pkg) = obj.get("package_name").and_then(|v| v.as_str()) {
        obj.insert("owner".to_string(), json!(pkg));
        obj.insert("owner_type".to_string(), json!("package"));
    } else if let Some(cmd) = obj.get("process_cmd").and_then(|v| v.as_str()) {
        obj.insert("owner".to_string(), json!(cmd));
        obj.insert("owner_type".to_string(), json!("process"));
    } else if obj
        .get("attribution_status")
        .and_then(|v| v.as_str())
        .is_none()
    {
        obj.insert("attribution_status".to_string(), json!("unresolved"));
        obj.insert("owner".to_string(), json!("unattributed"));
        obj.insert("owner_type".to_string(), json!("unknown"));
    } else {
        obj.remove("owner");
        obj.remove("owner_type");
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

/// After concurrent parsing, enrich network/logcat JSON using package and process maps.
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

    let process_map = results
        .iter()
        .find(|(pt, _, _)| *pt == ParserType::Process)
        .and_then(|(_, res, _)| res.as_ref().ok())
        .map(build_uid_process_map)
        .unwrap_or_default();

    if uid_map.is_empty() && process_map.is_empty() {
        for (pt, res, _) in results.iter_mut() {
            if *pt == ParserType::Network {
                if let Ok(v) = res {
                    enrich_network_sockets(v, &uid_map, &process_map);
                }
            }
        }
        return;
    }

    for (pt, res, _) in results.iter_mut() {
        if let Ok(v) = res {
            match pt {
                ParserType::Network => enrich_network_sockets(v, &uid_map, &process_map),
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
    fn parse_android_user_uid_app_and_system() {
        assert_eq!(parse_android_user_uid("u0_a109"), Some(10_109));
        assert_eq!(parse_android_user_uid("u10_a109"), Some(1_010_109));
        assert_eq!(parse_android_user_uid("system"), Some(1000));
        assert_eq!(parse_android_user_uid("u0_system"), Some(1000));
    }

    #[test]
    fn build_uid_process_map_prefers_package_like_cmd() {
        let processes = json!([
            {"pid": 200, "user": "u0_a109", "cmd": "binder:200_1"},
            {"pid": 100, "user": "u0_a109", "cmd": "com.example.app"}
        ]);
        let map = build_uid_process_map(&processes);
        let proc = map.get(&10_109).expect("uid mapped");
        assert_eq!(proc.cmd, "com.example.app");
        assert_eq!(proc.pid, 100);
    }

    #[test]
    fn enrich_network_socket_adds_package_name() {
        let mut network = json!({
            "sockets": [{"uid": 10333, "protocol": "tcp"}]
        });
        let mut map = HashMap::new();
        map.insert(10333, "com.example.app".to_string());
        enrich_network_sockets(&mut network, &map, &HashMap::new());
        assert_eq!(
            network["sockets"][0]["package_name"],
            "com.example.app"
        );
    }

    #[test]
    fn enrich_network_socket_falls_back_to_process() {
        let mut network = json!({
            "sockets": [{
                "uid": 1017,
                "protocol": "tcp",
                "remote_ip": "64:ff9b::253b:1955"
            }]
        });
        let mut process_map = HashMap::new();
        process_map.insert(
            1017,
            ProcessIdentity {
                pid: 659,
                cmd: "keystore2".to_string(),
                user: "u0_system".to_string(),
            },
        );
        enrich_network_sockets(&mut network, &HashMap::new(), &process_map);
        let sock = &network["sockets"][0];
        assert!(sock.get("package_name").is_none());
        assert_eq!(sock["process_cmd"], "keystore2");
        assert_eq!(sock["process_pid"], 659);
        assert_eq!(sock["owner"], "keystore2");
        assert_eq!(sock["owner_type"], "process");
    }

    #[test]
    fn stale_socket_with_uid_zero_is_not_attributed_to_root() {
        let mut network = json!({
            "sockets": [{
                "uid": 0,
                "inode": 0,
                "state": "LAST_ACK",
                "protocol": "tcp6",
                "remote_ipv4": "142.250.75.227"
            }]
        });
        let mut process_map = HashMap::new();
        process_map.insert(
            0,
            ProcessIdentity {
                pid: 335,
                cmd: "mivr_thread.mt6".to_string(),
                user: "root".to_string(),
            },
        );
        enrich_network_sockets(&mut network, &HashMap::new(), &process_map);
        let sock = &network["sockets"][0];
        assert_eq!(sock["attribution_status"], "stale_socket");
        assert_eq!(sock["owner"], "unattributed (stale socket)");
        assert!(sock.get("process_cmd").is_none());
    }

    #[test]
    fn fin_wait_with_hyphens_detected_as_stale() {
        let mut network = json!({
            "sockets": [{
                "state": "FIN-WAIT-1",
                "inode": 0,
                "remote_ip": "2a00:1450:4007:80c::200a",
                "protocol": "tcp"
            }]
        });
        enrich_network_sockets(&mut network, &HashMap::new(), &HashMap::new());
        let sock = &network["sockets"][0];
        assert_eq!(sock["attribution_status"], "stale_socket");
        assert_eq!(sock["owner"], "unattributed (stale socket)");
        assert_eq!(sock["peer_ip"], "2a00:1450:4007:80c::200a");
    }

    #[test]
    fn shared_system_uid_not_mapped_to_arbitrary_package() {
        let packages = json!([{
            "packages": [
                {
                    "package_name": "com.android.inputdevices",
                    "appId": 1000,
                    "sharedUser": "SharedUserSetting{5725ab7 android.uid.system/1000}"
                },
                {
                    "package_name": "com.sec.android.app.parser",
                    "appId": 1000,
                    "uid": 1000
                }
            ]
        }]);
        let map = build_uid_package_map(&packages);
        assert!(!map.contains_key(&1000));
    }

    #[test]
    fn listener_socket_uses_peer_ip_display_not_wildcard() {
        let mut network = json!({
            "sockets": [{
                "uid": 10097,
                "state": "LISTEN",
                "local_address": "[::]:40855",
                "remote_address": "[::]:*",
                "remote_ip": "::",
                "remote_ip_role": "any",
                "protocol": "tcp6"
            }]
        });
        let mut uid_map = HashMap::new();
        uid_map.insert(10097, "com.android.proxyhandler".to_string());
        enrich_network_sockets(&mut network, &uid_map, &HashMap::new());
        let sock = &network["sockets"][0];
        assert_eq!(sock["socket_direction"], "listen");
        assert_eq!(sock["peer_ip_display"], "(any)");
        assert!(sock["peer_ip"].is_null());
        assert_eq!(sock["owner"], "com.android.proxyhandler");
    }

    #[test]
    fn enrich_network_socket_netstat_program_overrides_uid_package() {
        let mut network = json!({
            "sockets": [{
                "uid": 10109,
                "protocol": "tcp",
                "remote_ip": "216.58.214.67",
                "program_name": "com.real.app",
                "program_pid": 4242
            }]
        });
        let mut uid_map = HashMap::new();
        uid_map.insert(10109, "com.wrong.app".to_string());
        enrich_network_sockets(&mut network, &uid_map, &HashMap::new());
        let sock = &network["sockets"][0];
        assert_eq!(sock["package_name"], "com.real.app");
        assert_eq!(sock["owner"], "com.real.app");
        assert_eq!(sock["owner_type"], "package");
    }

    #[test]
    fn enrich_network_socket_package_takes_priority_over_process() {
        let mut network = json!({
            "sockets": [{"uid": 10109, "protocol": "tcp"}]
        });
        let mut uid_map = HashMap::new();
        uid_map.insert(10109, "com.example.app".to_string());
        let mut process_map = HashMap::new();
        process_map.insert(
            10109,
            ProcessIdentity {
                pid: 1,
                cmd: "com.example.app".to_string(),
                user: "u0_a109".to_string(),
            },
        );
        enrich_network_sockets(&mut network, &uid_map, &process_map);
        let sock = &network["sockets"][0];
        assert_eq!(sock["package_name"], "com.example.app");
        assert!(sock.get("process_cmd").is_none());
    }
}
