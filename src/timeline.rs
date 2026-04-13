//! Timeline export in **JSONL** (and JSON array) for tools like [Timesketch](https://timesketch.org),
//! similar to `sysdiagnose-extractor-library`’s `timesketch` analyser output.
//!
//! Each line is one JSON object with Plaso/Timesketch-friendly fields:
//! `message`, `datetime` (RFC3339), `timestamp_desc`, `timestamp` (epoch microseconds),
//! `time_is_approximate`, `data_type`, `bugreport_parser`, plus parser-specific fields.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{json, Map, Value};
use std::error::Error;

use crate::parsers::ParserType;

const MAX_EVENTS_TOTAL: usize = 100_000;
const MAX_EVENTS_PER_PARSER: usize = 25_000;
const MAX_MESSAGE_CHARS: usize = 16_384;

/// Parsed bugreport timeline: JSON array (`events`) plus newline-delimited JSON (`jsonl`).
#[derive(Debug, Clone)]
pub struct TimelineExport {
    pub count: usize,
    pub events: Vec<Value>,
    pub jsonl: String,
}

fn parse_ts(timestamp: &str) -> Option<DateTime<Utc>> {
    let t = timestamp.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S%.3f") {
        return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
    }
    None
}

fn iso_to_micros(iso: &str) -> Option<i64> {
    parse_ts(iso).map(|d| d.timestamp_micros())
}

fn truncate_message(s: &str) -> String {
    s.chars().take(MAX_MESSAGE_CHARS).collect()
}

fn fallback_from_header(results: &[(ParserType, Result<Value, Box<dyn Error + Send + Sync>>, std::time::Duration)]) -> (String, bool) {
    for (pt, res, _) in results {
        if *pt != ParserType::Header {
            continue;
        }
        if let Ok(v) = res {
            if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
                if let Some(dt) = parse_ts(ts) {
                    return (dt.to_rfc3339(), false);
                }
                return (ts.to_string(), true);
            }
        }
    }
    (
        Utc::now().to_rfc3339(),
        true,
    )
}

fn push_event(
    out: &mut Vec<Value>,
    global: &mut usize,
    parser_budget: &mut usize,
    message: String,
    datetime: String,
    timestamp_desc: &str,
    time_approx: bool,
    parser_id: &str,
    data_type: &str,
    extra: Map<String, Value>,
) {
    if *global == 0 || *parser_budget == 0 {
        return;
    }
    let mut row = Map::new();
    row.insert("message".into(), json!(truncate_message(&message)));
    row.insert("datetime".into(), json!(datetime.clone()));
    row.insert("timestamp_desc".into(), json!(timestamp_desc));
    row.insert("time_is_approximate".into(), json!(time_approx));
    if let Some(us) = iso_to_micros(&datetime) {
        row.insert("timestamp".into(), json!(us));
    }
    row.insert("data_type".into(), json!(data_type));
    row.insert("bugreport_parser".into(), json!(parser_id));
    for (k, v) in extra {
        row.insert(k, v);
    }
    out.push(Value::Object(row));
    *global -= 1;
    *parser_budget -= 1;
}

fn flatten_header(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let Some(obj) = v.as_object() else {
        return;
    };
    let ts = obj.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
    let (datetime, approx) = if let Some(dt) = parse_ts(ts) {
        (dt.to_rfc3339(), false)
    } else {
        (fallback.0.clone(), true)
    };
    let mut parts: Vec<String> = Vec::new();
    for (k, val) in obj {
        if k == "other_lines" {
            continue;
        }
        parts.push(format!("{k}={}", val.as_str().unwrap_or(&val.to_string())));
    }
    let msg = format!("Bugreport header: {}", parts.join(", "));
    push_event(
        out,
        global,
        pb,
        msg,
        datetime,
        "bugreport_header",
        approx,
        "header",
        "android:bugreport:header",
        obj.clone(),
    );
}

fn flatten_memory(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let arr = match v.as_array() {
        Some(a) => a,
        None => return,
    };
    for (i, block) in arr.iter().enumerate() {
        let msg = format!("Memory snapshot {i}: {}", block.to_string());
        push_event(
            out,
            global,
            pb,
            msg,
            fallback.0.clone(),
            "memory_snapshot",
            fallback.1,
            "memory",
            "android:bugreport:memory",
            block.as_object().cloned().unwrap_or_default(),
        );
    }
}

fn flatten_process(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let Some(arr) = v.as_array() else {
        return;
    };
    for p in arr {
        let Some(o) = p.as_object() else {
            continue;
        };
        let pid = o.get("pid").map(|x| x.to_string()).unwrap_or_default();
        let user = o.get("user").and_then(|x| x.as_str()).unwrap_or("");
        let cmd = o.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
        let msg = format!("Process pid={pid} user={user} cmd={cmd}");
        push_event(
            out,
            global,
            pb,
            msg,
            fallback.0.clone(),
            "process_list",
            fallback.1,
            "process",
            "android:bugreport:process",
            o.clone(),
        );
    }
}

fn flatten_battery(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    if let Some(apps) = v.get("apps").and_then(|a| a.as_array()) {
        for app in apps {
            let Some(o) = app.as_object() else {
                continue;
            };
            let pkg = o
                .get("package_name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim_matches('"');
            let msg = format!("Battery stats app: {pkg}");
            push_event(
                out,
                global,
                pb,
                msg,
                fallback.0.clone(),
                "battery_app_stats",
                fallback.1,
                "battery",
                "android:bugreport:battery_app",
                o.clone(),
            );
        }
    }
    if let Some(hist) = v.get("battery_history").and_then(|a| a.as_array()) {
        for h in hist {
            let Some(o) = h.as_object() else {
                continue;
            };
            let ts = o.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
            let (datetime, approx) = parse_ts(ts)
                .map(|d| (d.to_rfc3339(), false))
                .unwrap_or_else(|| (fallback.0.clone(), true));
            let status = o.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = format!("Battery history: status={status}");
            push_event(
                out,
                global,
                pb,
                msg,
                datetime,
                "battery_history",
                approx,
                "battery",
                "android:bugreport:battery_history",
                o.clone(),
            );
        }
    }
}

fn flatten_power(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    if let Some(hist) = v.get("power_history").and_then(|a| a.as_array()) {
        for e in hist {
            let Some(o) = e.as_object() else {
                continue;
            };
            let ts = o.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
            let (datetime, approx) = parse_ts(ts)
                .map(|d| (d.to_rfc3339(), false))
                .unwrap_or_else(|| (fallback.0.clone(), true));
            let et = o.get("event_type").and_then(|x| x.as_str()).unwrap_or("");
            let msg = format!("Power event: {et}");
            push_event(
                out,
                global,
                pb,
                msg,
                datetime,
                "power_history",
                approx,
                "power",
                "android:bugreport:power",
                o.clone(),
            );
        }
    }
    if let Some(reasons) = v.get("reset_reasons").and_then(|a| a.as_array()) {
        for r in reasons {
            let Some(o) = r.as_object() else {
                continue;
            };
            let reason = o.get("reason").and_then(|x| x.as_str()).unwrap_or("");
            let msg = format!("Reset reason: {reason}");
            push_event(
                out,
                global,
                pb,
                msg,
                fallback.0.clone(),
                "reset_reason",
                fallback.1,
                "power",
                "android:bugreport:reset_reason",
                o.clone(),
            );
        }
    }
}

fn flatten_usb(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let Some(arr) = v.as_array().and_then(|a| a.first()) else {
        return;
    };
    if let Some(ports) = arr.get("ports").and_then(|a| a.as_array()) {
        for p in ports {
            if let Some(o) = p.as_object() {
                let id = o.get("id").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("USB port: {id}");
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    fallback.0.clone(),
                    "usb_port",
                    fallback.1,
                    "usb",
                    "android:bugreport:usb_port",
                    o.clone(),
                );
            }
        }
    }
    if let Some(devs) = arr.get("connected_devices").and_then(|a| a.as_array()) {
        for d in devs {
            if let Some(o) = d.as_object() {
                let prod = o.get("product_name").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("USB device: {prod}");
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    fallback.0.clone(),
                    "usb_device",
                    fallback.1,
                    "usb",
                    "android:bugreport:usb_device",
                    o.clone(),
                );
            }
        }
    }
}

fn flatten_crash(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    if let Some(tombs) = v.get("tombstones").and_then(|a| a.as_array()) {
        for t in tombs {
            let Some(o) = t.as_object() else {
                continue;
            };
            let proc = o.get("process_name").and_then(|x| x.as_str()).unwrap_or("");
            let sig = o.get("signal").and_then(|x| x.as_str()).unwrap_or("");
            let msg = format!("Native crash (tombstone): {proc} signal={sig}");
            let ts = o.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
            let (datetime, approx) = parse_ts(ts)
                .map(|d| (d.to_rfc3339(), false))
                .unwrap_or_else(|| (fallback.0.clone(), true));
            push_event(
                out,
                global,
                pb,
                msg,
                datetime.clone(),
                "tombstone",
                approx,
                "crash",
                "android:bugreport:tombstone",
                o.clone(),
            );
            if let Some(bt) = o.get("backtrace").and_then(|a| a.as_array()) {
                for (i, fr) in bt.iter().enumerate() {
                    let Some(fo) = fr.as_object() else {
                        continue;
                    };
                    let lib = fo.get("library").and_then(|x| x.as_str()).unwrap_or("");
                    let func = fo.get("function").and_then(|x| x.as_str()).unwrap_or("");
                    let fmsg = format!("Backtrace[{i}] {lib} {func}");
                    let mut ex = fo.clone();
                    ex.insert("tombstone_process".into(), json!(proc));
                    push_event(
                        out,
                        global,
                        pb,
                        fmsg,
                        datetime.clone(),
                        "tombstone_backtrace",
                        approx,
                        "crash",
                        "android:bugreport:tombstone_frame",
                        ex,
                    );
                }
            }
        }
    }
    if let Some(files) = v.get("anr_files").and_then(|a| a.get("files")).and_then(|x| x.as_array()) {
        for f in files {
            if let Some(o) = f.as_object() {
                let name = o.get("filename").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("ANR file: {name}");
                let ts = o.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
                let (datetime, approx) = parse_ts(ts)
                    .map(|d| (d.to_rfc3339(), false))
                    .unwrap_or_else(|| (fallback.0.clone(), true));
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    datetime,
                    "anr_file",
                    approx,
                    "crash",
                    "android:bugreport:anr_file",
                    o.clone(),
                );
            }
        }
    }
    if let Some(trace) = v.get("anr_trace") {
        let subj = trace
            .get("header")
            .and_then(|h| h.get("subject"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let msg = format!("ANR trace: {subj}");
        push_event(
            out,
            global,
            pb,
            msg,
            fallback.0.clone(),
            "anr_trace",
            fallback.1,
            "crash",
            "android:bugreport:anr_trace",
            trace
                .as_object()
                .cloned()
                .unwrap_or_default(),
        );
    }
}

fn flatten_network(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let Some(obj) = v.as_object() else {
        return;
    };
    if let Some(socks) = obj.get("sockets").and_then(|a| a.as_array()) {
        for s in socks {
            if let Some(o) = s.as_object() {
                let proto = o.get("protocol").and_then(|x| x.as_str()).unwrap_or("");
                let la = o.get("local_address").and_then(|x| x.as_str()).unwrap_or("");
                let ra = o.get("remote_address").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("Socket {proto} {la} -> {ra}");
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    fallback.0.clone(),
                    "network_socket",
                    fallback.1,
                    "network",
                    "android:bugreport:network_socket",
                    o.clone(),
                );
            }
        }
    }
    if let Some(ifaces) = obj.get("interfaces").and_then(|a| a.as_array()) {
        for iface in ifaces {
            if let Some(o) = iface.as_object() {
                let name = o.get("name").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("Interface {name}");
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    fallback.0.clone(),
                    "network_interface",
                    fallback.1,
                    "network",
                    "android:bugreport:network_interface",
                    o.clone(),
                );
            }
        }
    }
    if let Some(stats) = obj.get("network_stats").and_then(|a| a.as_array()) {
        for s in stats {
            if let Some(o) = s.as_object() {
                let nt = o.get("network_type").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("Network stats: {nt}");
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    fallback.0.clone(),
                    "network_stats",
                    fallback.1,
                    "network",
                    "android:bugreport:network_stats",
                    o.clone(),
                );
            }
        }
    }
    if let Some(wifi) = obj.get("wifi_scanner").and_then(|w| w.as_object()) {
        if let Some(saved) = wifi.get("saved_networks").and_then(|a| a.as_array()) {
            for ssid in saved {
                if let Some(s) = ssid.as_str() {
                    let msg = format!("WiFi saved network: {s}");
                    let mut ex = Map::new();
                    ex.insert("ssid".into(), json!(s));
                    push_event(
                        out,
                        global,
                        pb,
                        msg,
                        fallback.0.clone(),
                        "wifi_saved_network",
                        fallback.1,
                        "network",
                        "android:bugreport:wifi_saved",
                        ex,
                    );
                }
            }
        }
    }
}

fn flatten_bluetooth(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    if let Some(devs) = v.get("devices").and_then(|a| a.as_array()) {
        for d in devs {
            if let Some(o) = d.as_object() {
                let name = o.get("name").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("Bluetooth device: {name}");
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    fallback.0.clone(),
                    "bluetooth_device",
                    fallback.1,
                    "bluetooth",
                    "android:bugreport:bluetooth",
                    o.clone(),
                );
            }
        }
    }
}

fn flatten_package(
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let Some(sections) = v.as_array() else {
        return;
    };
    for section in sections {
        let Some(sec) = section.as_object() else {
            continue;
        };
        if let Some(logs) = sec.get("install_logs").and_then(|a| a.as_array()) {
            for log in logs {
                let Some(lo) = log.as_object() else {
                    continue;
                };
                let et = lo.get("event_type").and_then(|x| x.as_str()).unwrap_or("");
                let pkg = lo.get("pkg").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("Package install log: {et} pkg={pkg}");
                let ts = lo.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
                let (datetime, approx) = parse_ts(ts)
                    .map(|d| (d.to_rfc3339(), false))
                    .unwrap_or_else(|| (fallback.0.clone(), true));
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    datetime,
                    "package_install_log",
                    approx,
                    "package",
                    "android:bugreport:package_install",
                    lo.clone(),
                );
            }
        }
        if let Some(pkgs) = sec.get("packages").and_then(|a| a.as_array()) {
            for pkg in pkgs {
                let Some(po) = pkg.as_object() else {
                    continue;
                };
                let name = po.get("package_name").and_then(|x| x.as_str()).unwrap_or("");
                let msg = format!("Installed package metadata: {name}");
                let ts = po
                    .get("lastUpdateTime")
                    .or_else(|| po.get("firstInstallTime"))
                    .and_then(|x| x.as_str());
                let (datetime, approx) = ts
                    .and_then(parse_ts)
                    .map(|d| (d.to_rfc3339(), false))
                    .unwrap_or_else(|| (fallback.0.clone(), true));
                push_event(
                    out,
                    global,
                    pb,
                    msg,
                    datetime,
                    "package_metadata",
                    approx,
                    "package",
                    "android:bugreport:package_metadata",
                    po.clone(),
                );
            }
        }
    }
}

fn flatten_generic_json(
    pt: ParserType,
    v: &Value,
    fallback: &(String, bool),
    out: &mut Vec<Value>,
    global: &mut usize,
    pb: &mut usize,
) {
    let parser_id = format!("{pt:?}").to_lowercase();
    let dtype = format!("android:bugreport:{parser_id}");
    let msg = truncate_message(&format!("{parser_id} parser output: {}", v.to_string()));
    push_event(
        out,
        global,
        pb,
        msg,
        fallback.0.clone(),
        "parser_dump",
        fallback.1,
        &parser_id,
        &dtype,
        match v {
            Value::Object(m) => m.clone(),
            _ => {
                let mut m = Map::new();
                m.insert("raw".into(), v.clone());
                m
            }
        },
    );
}

/// Build timeline events and JSONL from concurrent parser results (`run_parsers_concurrently` output).
pub fn export_timeline(
    results: &[(ParserType, Result<Value, Box<dyn Error + Send + Sync>>, std::time::Duration)],
) -> TimelineExport {
    let fallback = fallback_from_header(results);
    let mut out: Vec<Value> = Vec::new();
    let mut global = MAX_EVENTS_TOTAL;

    for (pt, res, _) in results {
        let mut pb = MAX_EVENTS_PER_PARSER;
        let Ok(v) = res else {
            continue;
        };
        match pt {
            ParserType::Header => flatten_header(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Memory => flatten_memory(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Process => flatten_process(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Battery => flatten_battery(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Power => flatten_power(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Usb => flatten_usb(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Crash => flatten_crash(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Network => flatten_network(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Bluetooth => flatten_bluetooth(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::Package => flatten_package(v, &fallback, &mut out, &mut global, &mut pb),
            ParserType::DevicePolicy
            | ParserType::Adb
            | ParserType::Authentication
            | ParserType::Vpn
            | ParserType::Privacy => {
                flatten_generic_json(*pt, v, &fallback, &mut out, &mut global, &mut pb);
            }
        }
    }

    out.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|x| x.as_i64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|x| x.as_i64()).unwrap_or(0);
        ta.cmp(&tb)
    });

    let jsonl = events_to_jsonl(&out);
    let count = out.len();
    TimelineExport {
        count,
        events: out,
        jsonl,
    }
}

fn events_to_jsonl(events: &[Value]) -> String {
    let mut buf = String::new();
    for ev in events {
        let Ok(line) = serde_json::to_string(ev) else {
            continue;
        };
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(&line);
    }
    buf
}

/// Serialize timeline as a single JSON value (includes `events` array and `jsonl` string).
pub fn export_timeline_value(
    results: &[(ParserType, Result<Value, Box<dyn Error + Send + Sync>>, std::time::Duration)],
) -> Value {
    let exp = export_timeline(results);
    json!({
        "timeline_exporter": "bugreport_extractor_library",
        "count": exp.count,
        "events": exp.events,
        "jsonl": exp.jsonl,
        "note": "Plaso/Timesketch-style rows: message, datetime, timestamp_desc, timestamp (μs), time_is_approximate, data_type, bugreport_parser. When per-event time is missing, dumpstate header time is used (time_is_approximate=true). Save jsonl to a .jsonl file for streaming import."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::ParserType;
    use crate::run_parsers_concurrently;
    use crate::parsers::{HeaderParser, ProcessParser};
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn export_timeline_includes_header_and_process() {
        let data = br"
========================================================
== dumpstate: 2025-10-22 09:30:00
========================================================

Build: TEST
------ PROCESSES ------
";
        let parsers = vec![
            (ParserType::Header, Box::new(HeaderParser::new().unwrap()) as _),
            (
                ParserType::Process,
                Box::new(ProcessParser::new().unwrap()) as _,
            ),
        ];
        let content: Arc<[u8]> = Arc::from(data.as_slice());
        let results = run_parsers_concurrently(content, parsers);
        let exp = export_timeline(&results);
        assert!(!exp.jsonl.is_empty());
        assert!(exp.count >= 1);
        let v: Value = serde_json::from_str(exp.jsonl.lines().next().unwrap()).unwrap();
        assert!(v.get("message").is_some());
        assert!(v.get("bugreport_parser").is_some());
    }

    #[test]
    fn export_timeline_tombstone_backtrace_rows() {
        let v = json!({
            "tombstones": [{
                "timestamp": "2025-11-08 17:54:03",
                "pid": 1,
                "tid": 2,
                "uid": 100,
                "process_name": "com.test",
                "signal": "SIGSEGV",
                "code": "SEGV_MAPERR",
                "fault_addr": "0x0",
                "backtrace": [
                    {"frame": 0, "library": "/system/lib64/libc.so", "function": "foo"}
                ]
            }]
        });
        let results = [(ParserType::Crash, Ok(v), std::time::Duration::ZERO)];
        let exp = export_timeline(&results);
        assert!(exp.jsonl.contains("tombstone"));
        assert!(exp.jsonl.contains("Backtrace"));
    }
}
