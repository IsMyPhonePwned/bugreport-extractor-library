use serde_json::{json, Value};
use std::error::Error;
use sigma_zero::models::LogEntry;
use crate::parsers::ParserType;
use tracing::{warn, debug, info};

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
        match result {
            Ok(json_output) => {
                debug!("Attempting to extract Sigma log entries from {:?} parser", parser_type);
                match extract_entries_for_parser(parser_type, json_output) {
                    Some(entries) => {
                        if entries.is_empty() {
                            debug!("{:?} parser: No log entries extracted (empty result)", parser_type);
                        } else {
                            info!("{:?} parser: Extracted {} log entries for Sigma evaluation", parser_type, entries.len());
                            all_entries.push((parser_type.clone(), entries));
                        }
                    }
                    None => {
                        debug!("{:?} parser: No log entries extracted (extraction returned None)", parser_type);
                    }
                }
            }
            Err(e) => {
                warn!("{:?} parser failed, cannot extract Sigma log entries: {}", parser_type, e);
            }
        }
    }
    
    let total_entries: usize = all_entries.iter().map(|(_, entries)| entries.len()).sum();
    info!("Sigma conversion summary: {} parsers produced {} total log entries", all_entries.len(), total_entries);
    
    if all_entries.is_empty() {
        warn!("No Sigma-compatible log entries extracted from any parser. Check parser outputs and extraction functions.");
    }
    
    all_entries
}

/// Extracts log entries for a specific parser type
fn extract_entries_for_parser(parser_type: &ParserType, output: &Value) -> Option<Vec<LogEntry>> {
    let result = match parser_type {
        ParserType::Package => extract_package_entries(output),
        ParserType::Process => extract_process_entries(output),
        ParserType::Power => extract_power_entries(output),
        ParserType::Battery => extract_battery_entries(output),
        ParserType::Usb => extract_usb_entries(output),
        // Header and Memory parsers don't produce security-relevant events
        _ => {
            debug!("{:?} parser: No Sigma extraction function implemented", parser_type);
            None
        }
    };
    
    if result.is_none() {
        debug!("{:?} parser: Extraction function returned None", parser_type);
    }
    
    result
}

/// Extracts log entries from PackageParser output
/// PackageParser returns an array where each element can be:
/// 1. A service block with "install_logs" at the top level
/// 2. A packages section with "packages" array, where each package can have "install_logs" nested inside
fn extract_package_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    
    // Output is an array of sections
    let sections = match output.as_array() {
        Some(arr) => {
            debug!("Package parser: Found {} sections in output", arr.len());
            arr
        }
        None => {
            warn!("Package parser: Output is not an array, cannot extract log entries. Output type: {:?}", output);
            return None;
        }
    };
    
    let mut service_block_count = 0;
    let mut packages_section_count = 0;
    let mut total_service_logs = 0;
    let mut total_package_logs = 0;
    let mut total_packages_converted = 0;
    let mut conversion_errors = 0;
    
    for (section_idx, section) in sections.iter().enumerate() {
        debug!("Package parser: Processing section {} of {}", section_idx + 1, sections.len());
        
        // Log all keys in this section for debugging
        if let Some(section_obj) = section.as_object() {
            let section_keys: Vec<String> = section_obj.keys().cloned().collect();
            debug!("Package parser: Section {} has keys: {:?}", section_idx + 1, section_keys);
        }
        
        // Check for install_logs at the top level (service blocks)
        if let Some(logs) = section["install_logs"].as_array() {
            service_block_count += 1;
            total_service_logs += logs.len();
            debug!("Package parser: Section {} has {} install_logs at top level (service block)", section_idx + 1, logs.len());
            
            for (log_idx, log_entry) in logs.iter().enumerate() {
                // Try to extract package name from the log entry itself (it might have "pkg" field)
                // If not present, we can't add package_name for service block logs as they don't have package context
                let enriched_entry = log_entry.clone();
                
                match json_to_log_entry(enriched_entry) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        conversion_errors += 1;
                        warn!("Package parser: Failed to convert service block log entry {} in section {}: {}. Entry: {:?}", 
                            log_idx + 1, section_idx + 1, e, log_entry);
                        continue;
                    }
                }
            }
        } else {
            debug!("Package parser: Section {} does not have 'install_logs' at top level. Checking if it's a service block with other keys...", section_idx + 1);
            // Check if this is a service block (has pid, client_pids, threads) but no install_logs
            if section.get("pid").is_some() || section.get("client_pids").is_some() {
                debug!("Package parser: Section {} appears to be a service block (has pid/client_pids) but no install_logs found", section_idx + 1);
            }
        }
        
        // Check for packages section - convert each package to a log entry
        if let Some(packages) = section["packages"].as_array() {
            packages_section_count += 1;
            debug!("Package parser: Section {} has {} packages", section_idx + 1, packages.len());
            
            let mut packages_converted = 0;
            let mut install_logs_converted = 0;
            
            for (pkg_idx, package) in packages.iter().enumerate() {
                let pkg_name = package["package_name"].as_str().unwrap_or("unknown");
                
                // Convert the package itself to a log entry (package_name, lastUpdateTime, resourcePath, etc.)
                // Create a copy of the package object, but exclude nested structures like "users" and "install_logs"
                // that should be handled separately
                let mut package_entry = json!({});
                if let Some(package_obj) = package.as_object() {
                    for (key, value) in package_obj.iter() {
                        // Skip nested objects/arrays that should be handled separately
                        if key == "users" || key == "install_logs" {
                            continue;
                        }
                        // Include all other fields (package_name, lastUpdateTime, resourcePath, etc.)
                        package_entry[key] = value.clone();
                    }
                }
                
                // Convert package metadata to log entry
                match json_to_log_entry(package_entry.clone()) {
                    Ok(entry) => {
                        entries.push(entry);
                        packages_converted += 1;
                        total_packages_converted += 1;
                        debug!("Package parser: Converted package {} ({}) to log entry", pkg_idx + 1, pkg_name);
                    }
                    Err(e) => {
                        conversion_errors += 1;
                        warn!("Package parser: Failed to convert package {} ({}) to log entry: {}. Package: {:?}", 
                            pkg_idx + 1, pkg_name, e, package_entry);
                    }
                }
                
                // Also handle install_logs if they exist (for backward compatibility)
                if let Some(logs) = package["install_logs"].as_array() {
                    if !logs.is_empty() {
                        install_logs_converted += logs.len();
                        debug!("Package parser: Package {} ({}) has {} install_logs", pkg_idx + 1, pkg_name, logs.len());
                        
                        for (log_idx, log_entry) in logs.iter().enumerate() {
                            // Add package_name to the log entry if not already present
                            let mut enriched_entry = log_entry.clone();
                            if let Some(entry_obj) = enriched_entry.as_object_mut() {
                                // Only add package_name if it's not already in the log entry
                                if !entry_obj.contains_key("package_name") && !entry_obj.contains_key("pkg") {
                                    entry_obj.insert("package_name".to_string(), json!(pkg_name));
                                }
                            }
                            
                            match json_to_log_entry(enriched_entry) {
                                Ok(entry) => entries.push(entry),
                                Err(e) => {
                                    conversion_errors += 1;
                                    warn!("Package parser: Failed to convert install_log entry {} for package {} ({}): {}. Entry: {:?}", 
                                        log_idx + 1, pkg_idx + 1, pkg_name, e, log_entry);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            
            debug!("Package parser: Section {} packages summary: {} packages converted, {} install_logs converted", 
                section_idx + 1, packages_converted, install_logs_converted);
            total_package_logs += install_logs_converted;
        } else {
            debug!("Package parser: Section {} does not have 'packages' array", section_idx + 1);
        }
    }
    
    debug!("Package parser: Summary - {} service blocks ({} logs), {} packages sections ({} packages, {} install_logs), {} conversion errors, {} total entries extracted", 
        service_block_count, total_service_logs, packages_section_count, total_packages_converted, total_package_logs, conversion_errors, entries.len());
    
    if entries.is_empty() {
        warn!("Package parser: No log entries extracted. Found {} sections, {} service blocks, {} packages sections", 
            sections.len(), service_block_count, packages_section_count);
        None
    } else {
        Some(entries)
    }
}

/// Extracts log entries from ProcessParser output
fn extract_process_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    
    let processes = match output.as_array() {
        Some(arr) => {
            debug!("Process parser: Found {} processes in output", arr.len());
            arr
        }
        None => {
            warn!("Process parser: Output is not an array, cannot extract log entries. Output type: {:?}", output);
            return None;
        }
    };
    
    let mut conversion_errors = 0;
    
    for (idx, process) in processes.iter().enumerate() {
        let pid = match process["pid"].as_u64() {
            Some(p) => p,
            None => {
                warn!("Process parser: Process {} missing 'pid' field, skipping", idx + 1);
                conversion_errors += 1;
                continue;
            }
        };
        
        let user = match process["user"].as_str() {
            Some(u) => u,
            None => {
                warn!("Process parser: Process {} (pid {}) missing 'user' field, skipping", idx + 1, pid);
                conversion_errors += 1;
                continue;
            }
        };
        
        let cmd = match process["cmd"].as_str() {
            Some(c) => c,
            None => {
                warn!("Process parser: Process {} (pid {}, user {}) missing 'cmd' field, skipping", idx + 1, pid, user);
                conversion_errors += 1;
                continue;
            }
        };
        
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
                conversion_errors += 1;
                warn!("Process parser: Failed to convert process {} (pid {}, user {}, cmd {}): {}", idx + 1, pid, user, cmd, e);
                continue;
            }
        }
    }
    
    debug!("Process parser: Extracted {} entries from {} processes ({} conversion errors)", entries.len(), processes.len(), conversion_errors);
    
    if entries.is_empty() && conversion_errors > 0 {
        warn!("Process parser: No log entries extracted due to {} conversion errors", conversion_errors);
        None
    } else {
        Some(entries)
    }
}

/// Extracts log entries from PowerParser output
fn extract_power_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let mut conversion_errors = 0;
    
    debug!("Power parser: Starting extraction from output");
    
    // Extract power history events
    if let Some(history) = output["power_history"].as_array() {
        debug!("Power parser: Found {} power history events", history.len());
        for (idx, event) in history.iter().enumerate() {
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
                    conversion_errors += 1;
                    warn!("Power parser: Failed to convert power history event {}: {}. Event: {:?}", idx + 1, e, event);
                    continue;
                }
            }
        }
    } else {
        debug!("Power parser: No 'power_history' array found in output");
    }
    
    // Extract reset reasons
    if let Some(reasons) = output["reset_reasons"].as_array() {
        debug!("Power parser: Found {} reset reasons", reasons.len());
        for (idx, reason) in reasons.iter().enumerate() {
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
                    conversion_errors += 1;
                    warn!("Power parser: Failed to convert reset reason {}: {}. Reason: {:?}", idx + 1, e, reason);
                    continue;
                }
            }
        }
    } else {
        debug!("Power parser: No 'reset_reasons' array found in output");
    }
    
    debug!("Power parser: Extracted {} entries ({} conversion errors)", entries.len(), conversion_errors);
    
    if entries.is_empty() {
        debug!("Power parser: No log entries extracted");
        None
    } else {
        Some(entries)
    }
}

/// Extracts log entries from BatteryParser output
fn extract_battery_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    
    let sections = match output.as_array() {
        Some(arr) => {
            debug!("Battery parser: Found {} sections in output", arr.len());
            arr
        }
        None => {
            warn!("Battery parser: Output is not an array, cannot extract log entries. Output type: {:?}", output);
            return None;
        }
    };
    
    let mut conversion_errors = 0;
    let mut hsp_count = 0;
    let mut version_info_count = 0;
    
    for (section_idx, section) in sections.iter().enumerate() {
        // Extract HSP (High Power Service) records
        if let Some(hsp_records) = section["hsp_records"].as_array() {
            hsp_count += hsp_records.len();
            debug!("Battery parser: Section {} has {} HSP records", section_idx + 1, hsp_records.len());
            for (idx, hsp) in hsp_records.iter().enumerate() {
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
                        conversion_errors += 1;
                        warn!("Battery parser: Failed to convert HSP record {} in section {}: {}. HSP: {:?}", idx + 1, section_idx + 1, e, hsp);
                        continue;
                    }
                }
            }
        } else {
            debug!("Battery parser: Section {} does not have 'hsp_records'", section_idx + 1);
        }
        
        // Extract version info
        if let Some(version_info) = section.get("version_info") {
            version_info_count += 1;
            debug!("Battery parser: Section {} has version_info", section_idx + 1);
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
                    conversion_errors += 1;
                    warn!("Battery parser: Failed to convert version_info in section {}: {}. Version: {:?}", section_idx + 1, e, version_info);
                    continue;
                }
            }
        } else {
            debug!("Battery parser: Section {} does not have 'version_info'", section_idx + 1);
        }
    }
    
    debug!("Battery parser: Extracted {} entries from {} HSP records and {} version_info entries ({} conversion errors)", 
        entries.len(), hsp_count, version_info_count, conversion_errors);
    
    if entries.is_empty() {
        debug!("Battery parser: No log entries extracted");
        None
    } else {
        Some(entries)
    }
}

/// Extracts log entries from UsbParser output
fn extract_usb_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    
    let usb_array = match output.as_array() {
        Some(arr) => {
            debug!("USB parser: Found {} elements in output", arr.len());
            arr
        }
        None => {
            warn!("USB parser: Output is not an array, cannot extract log entries. Output type: {:?}", output);
            return None;
        }
    };
    
    let usb_info = match usb_array.get(0) {
        Some(info) => info,
        None => {
            warn!("USB parser: Output array is empty, cannot extract log entries");
            return None;
        }
    };
    
    let mut conversion_errors = 0;
    let mut port_count = 0;
    let mut device_count = 0;
    
    // Extract USB port events
    if let Some(ports) = usb_info["ports"].as_array() {
        port_count = ports.len();
        debug!("USB parser: Found {} USB ports", port_count);
        for (idx, port) in ports.iter().enumerate() {
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
                    conversion_errors += 1;
                    let port_id = port["id"].as_str().unwrap_or("unknown");
                    warn!("USB parser: Failed to convert USB port {} (id: {}): {}. Port: {:?}", idx + 1, port_id, e, port);
                    continue;
                }
            }
        }
    } else {
        debug!("USB parser: No 'ports' array found in USB info");
    }
    
    // Extract connected USB devices
    if let Some(devices) = usb_info["connected_devices"].as_array() {
        device_count = devices.len();
        debug!("USB parser: Found {} USB devices", device_count);
        for (idx, device) in devices.iter().enumerate() {
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
                    conversion_errors += 1;
                    let vid = device["vid"].as_str().unwrap_or("unknown");
                    let pid = device["pid"].as_str().unwrap_or("unknown");
                    warn!("USB parser: Failed to convert USB device {} (vid: {}, pid: {}): {}. Device: {:?}", idx + 1, vid, pid, e, device);
                    continue;
                }
            }
        }
    } else {
        debug!("USB parser: No 'connected_devices' array found in USB info");
    }
    
    debug!("USB parser: Extracted {} entries from {} ports and {} devices ({} conversion errors)", 
        entries.len(), port_count, device_count, conversion_errors);
    
    if entries.is_empty() {
        debug!("USB parser: No log entries extracted");
        None
    } else {
        Some(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_package_entries() {
        // Test service block with install_logs at top level
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
        
        // Test packages section with nested install_logs
        // Now we convert both the package metadata AND install_logs
        let output2 = json!([
            {
                "packages": [
                    {
                        "package_name": "com.example.app",
                        "lastUpdateTime": "2025-03-28 02:22:45",
                        "resourcePath": "/data/app/com.example.app",
                        "install_logs": [
                            {
                                "timestamp": "2025-03-28 02:22:45.340",
                                "event_type": "START_INSTALL",
                                "pkg": "com.example.app"
                            }
                        ]
                    }
                ]
            }
        ]);
        
        let entries2 = extract_package_entries(&output2).unwrap();
        // Should have 2 entries: 1 for package metadata + 1 for install_log
        assert_eq!(entries2.len(), 2);
        
        // Test mixed structure (both service block and packages)
        // Now we convert both package metadata AND install_logs
        let output3 = json!([
            {
                "install_logs": [
                    {
                        "timestamp": "2025-03-28 02:22:45.340",
                        "event_type": "START_INSTALL",
                        "pkg": "com.deleted.app"
                    }
                ]
            },
            {
                "packages": [
                    {
                        "package_name": "com.example.app",
                        "lastUpdateTime": "2025-03-28 02:22:46",
                        "resourcePath": "/data/app/com.example.app",
                        "install_logs": [
                            {
                                "timestamp": "2025-03-28 02:22:46.340",
                                "event_type": "START_INSTALL",
                                "pkg": "com.example.app"
                            }
                        ]
                    }
                ]
            }
        ]);
        
        let entries3 = extract_package_entries(&output3).unwrap();
        // Should have 3 entries: 1 service block log + 1 package metadata + 1 package install_log
        assert_eq!(entries3.len(), 3);
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