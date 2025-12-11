use serde_json::{json, Value};
use std::error::Error;
use sigma_zero::models::LogEntry;
use crate::parsers::ParserType;
use tracing::warn;

/// Helper function to create a LogEntry from a JSON Value
fn json_to_log_entry(value: Value) -> Result<LogEntry, Box<dyn Error + Send + Sync>> {
    // Convert Value to string then deserialize to LogEntry
    // This matches how sigma-zero expects LogEntry to be created
    let json_str = serde_json::to_string(&value)?;
    let log_entry: LogEntry = serde_json::from_str(&json_str)?;
    Ok(log_entry)
}

/// Trait for parsers that can produce Sigma-compatible log entries
pub trait SigmaCompatible {
    /// Extracts log entries from the parser's JSON output
    /// Returns a vector of LogEntry objects that can be evaluated against Sigma rules
    fn extract_log_entries(&self, output: &Value) -> Result<Vec<LogEntry>, Box<dyn Error + Send + Sync>>;
}

/// Configuration for Sigma rule evaluation
#[derive(Debug, Clone)]
pub struct SigmaConfig {
    pub min_level: Option<String>,
    pub output_format: String,
}

impl Default for SigmaConfig {
    fn default() -> Self {
        Self {
            min_level: None,
            output_format: "text".to_string(),
        }
    }
}

/// Extracts log entries from all parser results that support Sigma
pub fn extract_all_log_entries(
    results: &[(ParserType, Result<Value, Box<dyn Error + Send + Sync>>, std::time::Duration)]
) -> Vec<(ParserType, Vec<LogEntry>)> {
    let mut all_entries = Vec::new();
    
    for (parser_type, result, _duration) in results {
        if let Ok(json_output) = result {
            if let Some(entries) = extract_entries_for_parser(parser_type, json_output) {
                all_entries.push((parser_type.clone(), entries));
            }
        }
    }
    
    all_entries
}

/// Extracts log entries for a specific parser type
fn extract_entries_for_parser(parser_type: &ParserType, output: &Value) -> Option<Vec<LogEntry>> {
    match parser_type {
        ParserType::Package => extract_package_entries(output),
        ParserType::Process => extract_process_entries(output),
        ParserType::Power => extract_power_entries(output),
        ParserType::Battery => extract_battery_entries(output),
        ParserType::Usb => extract_usb_entries(output),
        // Header and Memory parsers don't produce security-relevant events
        _ => None,
    }
}

/// Extracts log entries from PackageParser output
fn extract_package_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    
    // Navigate to install_logs: output is an array with first element containing install_logs
    let first_array = output.as_array()?;
    let first_item = first_array.get(0)?;
    let logs = first_item["install_logs"].as_array()?;
    
    for log_entry in logs {
        // The log entries are already in the correct format for LogEntry
        match json_to_log_entry(log_entry.clone()) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                warn!("Failed to parse package log entry: {}", e);
                continue;
            }
        }
    }
    
    Some(entries)
}

/// Extracts log entries from ProcessParser output
fn extract_process_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let processes = output.as_array()?;
    
    for process in processes {
        let pid = process["pid"].as_u64()?;
        let user = process["user"].as_str()?;
        let cmd = process["cmd"].as_str()?;
        
        // Build JSON object for LogEntry
        let mut log_json = json!({
            "event_type": "process_running",
            "pid": pid,
            "user": user,
            "cmd": cmd
        });
        
        // Add thread information if available
        if let Some(threads) = process["threads"].as_array() {
            log_json["thread_count"] = json!(threads.len());
        }
        
        // Convert to LogEntry
        match json_to_log_entry(log_json) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                warn!("Failed to create process log entry: {}", e);
                continue;
            }
        }
    }
    
    Some(entries)
}

/// Extracts log entries from PowerParser output
fn extract_power_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    
    // Extract power history events
    if let Some(history) = output["power_history"].as_array() {
        for event in history {
            let mut log_json = json!({
                "event_type": "power_event"
            });
            
            if let Some(timestamp) = event["timestamp"].as_str() {
                log_json["timestamp"] = json!(timestamp);
            }
            if let Some(event_type) = event["event_type"].as_str() {
                log_json["power_event_type"] = json!(event_type);
            }
            if let Some(flags) = event["flags"].as_str() {
                log_json["flags"] = json!(flags);
            }
            if let Some(details) = event["details"].as_str() {
                log_json["details"] = json!(details);
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Failed to create power event log entry: {}", e);
                    continue;
                }
            }
        }
    }
    
    // Extract reset reasons
    if let Some(reasons) = output["reset_reasons"].as_array() {
        for reason in reasons {
            let mut log_json = json!({
                "event_type": "reset_reason"
            });
            
            if let Some(reason_text) = reason["reason"].as_str() {
                log_json["reason"] = json!(reason_text);
            }
            if let Some(stack_trace) = reason["stack_trace"].as_array() {
                let traces: Vec<String> = stack_trace
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                log_json["stack_trace"] = json!(traces.join("\n"));
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Failed to create reset reason log entry: {}", e);
                    continue;
                }
            }
        }
    }
    
    Some(entries)
}

/// Extracts log entries from BatteryParser output
fn extract_battery_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let sections = output.as_array()?;
    
    for section in sections {
        // Extract HSP (High Power Service) records
        if let Some(hsp_records) = section["hsp_records"].as_array() {
            for hsp in hsp_records {
                let mut log_json = json!({
                    "event_type": "battery_hsp"
                });
                
                if let Some(uid) = hsp["uid"].as_u64() {
                    log_json["uid"] = json!(uid);
                }
                if let Some(name) = hsp["name"].as_str() {
                    log_json["pkg"] = json!(name);
                }
                if let Some(index) = hsp["index"].as_u64() {
                    log_json["index"] = json!(index);
                }
                
                match json_to_log_entry(log_json) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        warn!("Failed to create battery HSP log entry: {}", e);
                        continue;
                    }
                }
            }
        }
        
        // Extract version info
        if let Some(version_info) = section.get("version_info") {
            let mut log_json = json!({
                "event_type": "battery_version"
            });
            
            if let Some(sdk) = version_info["sdk_version"].as_u64() {
                log_json["sdk_version"] = json!(sdk);
            }
            if let Some(build) = version_info["build_number_1"].as_str() {
                log_json["build_number"] = json!(build);
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Failed to create battery version log entry: {}", e);
                    continue;
                }
            }
        }
    }
    
    Some(entries)
}

/// Extracts log entries from UsbParser output
fn extract_usb_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let usb_info = output.as_array()?.get(0)?;
    
    // Extract USB port events
    if let Some(ports) = usb_info["ports"].as_array() {
        for port in ports {
            let mut log_json = json!({
                "event_type": "usb_port"
            });
            
            if let Some(id) = port["id"].as_str() {
                log_json["port_id"] = json!(id);
            }
            if let Some(connected) = port["connected"].as_bool() {
                log_json["connected"] = json!(connected);
            }
            if let Some(mode) = port["current_mode"].as_str() {
                log_json["mode"] = json!(mode);
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Failed to create USB port log entry: {}", e);
                    continue;
                }
            }
        }
    }
    
    // Extract connected USB devices
    if let Some(devices) = usb_info["connected_devices"].as_array() {
        for device in devices {
            let mut log_json = json!({
                "event_type": "usb_device"
            });
            
            if let Some(vid) = device["vid"].as_str() {
                log_json["vendor_id"] = json!(vid);
            }
            if let Some(pid) = device["pid"].as_str() {
                log_json["product_id"] = json!(pid);
            }
            if let Some(product) = device["product_name"].as_str() {
                log_json["product_name"] = json!(product);
            }
            if let Some(manufacturer) = device["manufacturer"].as_str() {
                log_json["manufacturer"] = json!(manufacturer);
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Failed to create USB device log entry: {}", e);
                    continue;
                }
            }
        }
    }
    
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_package_entries() {
        let output = json!([
            {
                "install_logs": [
                    {
                        "timestamp": "2025-03-28 02:22:45.340",
                        "event_type": "START_INSTALL",
                        "pkg": "com.example.app"
                    }
                ]
            }
        ]);
        
        let entries = extract_package_entries(&output).unwrap();
        assert_eq!(entries.len(), 1);
        // Note: We can't easily test LogEntry contents without knowing its internal structure
        // The main thing is that it doesn't panic and returns the right count
    }

    #[test]
    fn test_extract_process_entries() {
        let output = json!([
            {
                "pid": 1234,
                "user": "system",
                "cmd": "system_server",
                "threads": [
                    {"tid": 1234},
                    {"tid": 1235}
                ]
            }
        ]);
        
        let entries = extract_process_entries(&output).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_extract_usb_entries() {
        let output = json!([
            {
                "ports": [
                    {
                        "id": "port0",
                        "connected": true,
                        "current_mode": "device"
                    }
                ],
                "connected_devices": [
                    {
                        "vid": "1234",
                        "pid": "5678",
                        "product_name": "Test Device"
                    }
                ]
            }
        ]);
        
        let entries = extract_usb_entries(&output).unwrap();
        assert_eq!(entries.len(), 2); // 1 port + 1 device
    }
    
    #[test]
    fn test_json_to_log_entry_helper() {
        let json_value = json!({
            "event_type": "test",
            "field1": "value1",
            "field2": 123
        });
        
        let result = json_to_log_entry(json_value);
        assert!(result.is_ok());
    }
}