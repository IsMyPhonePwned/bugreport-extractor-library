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
        ParserType::Crash => extract_crash_entries(output),
        ParserType::Bluetooth => extract_bluetooth_entries(output),
        ParserType::Network => extract_network_entries(output),
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
///
/// Install log entries include fields like:
/// - timestamp, event_type, pkg, versionCode
/// - initiatingPackageName: The package that initiated the installation
/// - originatingPackageName: The package where the install originated from
/// - installerPackageName: The installer package
/// - observer, stagedDir, request_from
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
    let mut conversion_errors = 0;
    let mut apps_count = 0;
    let mut history_count = 0;
    
    // Battery parser returns an object with "apps", "hardware_info", "battery_history", "version_info"
    if !output.is_object() {
        warn!("Battery parser: Output is not an object, cannot extract log entries");
        return None;
    }
    
    // Extract from "apps" array (AppBatteryStats)
    if let Some(apps) = output["apps"].as_array() {
        apps_count = apps.len();
        debug!("Battery parser: Found {} apps in output", apps_count);
        
        for (idx, app) in apps.iter().enumerate() {
            let mut log_json = json!({
                "event_type": "battery_app_stats"
            });
            
            // Copy all fields from AppBatteryStats
            if let Some(uid) = app["uid"].as_u64() {
                log_json["uid"] = json!(uid);
            }
            if let Some(pkg) = app["package_name"].as_str() {
                log_json["package_name"] = json!(pkg.trim_matches('"'));
            }
            if let Some(cpu_user) = app["cpu_user_time_ms"].as_u64() {
                log_json["cpu_user_time_ms"] = json!(cpu_user);
            }
            if let Some(cpu_system) = app["cpu_system_time_ms"].as_u64() {
                log_json["cpu_system_time_ms"] = json!(cpu_system);
            }
            if let Some(fg_service) = app["foreground_service_time_ms"].as_u64() {
                log_json["foreground_service_time_ms"] = json!(fg_service);
            }
            if let Some(net_bytes) = app["total_network_bytes"].as_u64() {
                log_json["total_network_bytes"] = json!(net_bytes);
            }
            if let Some(wakelock_time) = app["total_wakelock_time_ms"].as_u64() {
                log_json["total_wakelock_time_ms"] = json!(wakelock_time);
            }
            if let Some(job_count) = app["total_job_count"].as_u64() {
                log_json["total_job_count"] = json!(job_count);
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Battery parser: Failed to convert app {} to log entry: {}. App: {:?}", idx + 1, e, app);
                }
            }
        }
    }
    
    // Extract from "battery_history" array
    if let Some(history) = output["battery_history"].as_array() {
        history_count = history.len();
        debug!("Battery parser: Found {} battery history entries", history_count);
        
        for (idx, entry_data) in history.iter().enumerate() {
            let mut log_json = json!({
                "event_type": "battery_history"
            });
            
            // Copy fields from BatteryHistoryEntry
            if let Some(timestamp) = entry_data["timestamp"].as_str() {
                log_json["timestamp"] = json!(timestamp);
            }
            if let Some(status) = entry_data["status"].as_str() {
                log_json["status"] = json!(status);
            }
            if let Some(volt) = entry_data["volt"].as_u64() {
                log_json["volt"] = json!(volt);
            }
            if let Some(temp) = entry_data["temp"].as_u64() {
                log_json["temp"] = json!(temp);
            }
            if let Some(charge) = entry_data["charge"].as_u64() {
                log_json["charge"] = json!(charge);
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Battery parser: Failed to convert battery history entry {}: {}. Entry: {:?}", idx + 1, e, entry_data);
                }
            }
        }
    }
    
    debug!("Battery parser: Extracted {} total entries ({} from apps, {} from history, {} conversion errors)", 
        entries.len(), apps_count, history_count, conversion_errors);
    
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

/// Extracts log entries from BluetoothParser output
/// BluetoothParser returns an object with "devices" array; each device has mac_address, masked_address,
/// name, transport_type, device_class, services, connected, manufacturer, device_type, link_type
fn extract_bluetooth_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let mut conversion_errors = 0;

    let devices = match output.get("devices").and_then(|v| v.as_array()) {
        Some(arr) => {
            debug!("Bluetooth parser: Found {} devices in output", arr.len());
            arr
        }
        None => {
            debug!("Bluetooth parser: No 'devices' array found in output");
            return None;
        }
    };

    for (idx, device) in devices.iter().enumerate() {
        let mut log_json = json!({
            "event_type": "bluetooth_device"
        });

        if let Some(v) = device.get("mac_address").and_then(|v| v.as_str()) {
            log_json["mac_address"] = json!(v);
        }
        if let Some(v) = device.get("masked_address").and_then(|v| v.as_str()) {
            log_json["masked_address"] = json!(v);
        }
        if let Some(v) = device.get("identity_address").and_then(|v| v.as_str()) {
            log_json["identity_address"] = json!(v);
        }
        if let Some(v) = device.get("name").and_then(|v| v.as_str()) {
            log_json["name"] = json!(v);
        }
        if let Some(v) = device.get("transport_type").and_then(|v| v.as_str()) {
            log_json["transport_type"] = json!(v);
        }
        if let Some(v) = device.get("device_class").and_then(|v| v.as_str()) {
            log_json["device_class"] = json!(v);
        }
        if let Some(connected) = device.get("connected").and_then(|v| v.as_bool()) {
            log_json["connected"] = json!(connected);
        }
        if let Some(services) = device.get("services").and_then(|v| v.as_array()) {
            let svc: Vec<&str> = services.iter().filter_map(|v| v.as_str()).collect();
            if !svc.is_empty() {
                log_json["services"] = json!(svc);
            }
        }
        if let Some(v) = device.get("manufacturer").and_then(|v| v.as_u64()) {
            log_json["manufacturer"] = json!(v);
        }
        if let Some(v) = device.get("device_type").and_then(|v| v.as_u64()) {
            log_json["device_type"] = json!(v);
        }
        if let Some(v) = device.get("link_type").and_then(|v| v.as_u64()) {
            log_json["link_type"] = json!(v);
        }

        match json_to_log_entry(log_json) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                conversion_errors += 1;
                warn!(
                    "Bluetooth parser: Failed to convert device {}: {}. Device: {:?}",
                    idx + 1,
                    e,
                    device
                );
            }
        }
    }

    debug!(
        "Bluetooth parser: Extracted {} entries from {} devices ({} conversion errors)",
        entries.len(),
        devices.len(),
        conversion_errors
    );

    if entries.is_empty() {
        debug!("Bluetooth parser: No log entries extracted");
        None
    } else {
        Some(entries)
    }
}

/// Extracts log entries from NetworkParser output
/// NetworkParser returns an object with optional "sockets", "interfaces", "network_stats", "wifi_scanner"
fn extract_network_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let mut conversion_errors = 0;

    // Sockets: protocol, local_address, remote_address, local_ip, local_port, remote_ip, remote_port, state, uid, inode, ...
    if let Some(sockets) = output.get("sockets").and_then(|v| v.as_array()) {
        debug!("Network parser: Found {} sockets", sockets.len());
        for (idx, sock) in sockets.iter().enumerate() {
            let mut log_json = json!({ "event_type": "network_socket" });
            if let Some(v) = sock.get("protocol").and_then(|v| v.as_str()) {
                log_json["protocol"] = json!(v);
            }
            if let Some(v) = sock.get("local_address").and_then(|v| v.as_str()) {
                log_json["local_address"] = json!(v);
            }
            if let Some(v) = sock.get("remote_address").and_then(|v| v.as_str()) {
                log_json["remote_address"] = json!(v);
            }
            if let Some(v) = sock.get("local_ip").and_then(|v| v.as_str()) {
                log_json["local_ip"] = json!(v);
            }
            if let Some(v) = sock.get("local_port").and_then(|v| v.as_u64()) {
                log_json["local_port"] = json!(v);
            }
            if let Some(v) = sock.get("remote_ip").and_then(|v| v.as_str()) {
                log_json["remote_ip"] = json!(v);
            }
            if let Some(v) = sock.get("remote_port").and_then(|v| v.as_u64()) {
                log_json["remote_port"] = json!(v);
            }
            if let Some(v) = sock.get("state").and_then(|v| v.as_str()) {
                log_json["state"] = json!(v);
            }
            if let Some(v) = sock.get("uid").and_then(|v| v.as_u64()) {
                log_json["uid"] = json!(v);
            }
            if let Some(v) = sock.get("inode").and_then(|v| v.as_u64()) {
                log_json["inode"] = json!(v);
            }
            if let Some(v) = sock.get("recv_q").and_then(|v| v.as_u64()) {
                log_json["recv_q"] = json!(v);
            }
            if let Some(v) = sock.get("send_q").and_then(|v| v.as_u64()) {
                log_json["send_q"] = json!(v);
            }
            if let Some(v) = sock.get("socket_key").and_then(|v| v.as_str()) {
                log_json["socket_key"] = json!(v);
            }
            if let Some(v) = sock.get("additional_info").and_then(|v| v.as_str()) {
                log_json["additional_info"] = json!(v);
            }
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Network parser: Failed to convert socket {}: {}", idx + 1, e);
                }
            }
        }
    }

    // Interfaces: name, ip_addresses, flags, mtu, rx_bytes, tx_bytes
    if let Some(interfaces) = output.get("interfaces").and_then(|v| v.as_array()) {
        debug!("Network parser: Found {} interfaces", interfaces.len());
        for (idx, iface) in interfaces.iter().enumerate() {
            let mut log_json = json!({ "event_type": "network_interface" });
            if let Some(v) = iface.get("name").and_then(|v| v.as_str()) {
                log_json["name"] = json!(v);
            }
            if let Some(arr) = iface.get("ip_addresses").and_then(|v| v.as_array()) {
                let ips: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                if !ips.is_empty() {
                    log_json["ip_addresses"] = json!(ips);
                }
            }
            if let Some(arr) = iface.get("flags").and_then(|v| v.as_array()) {
                let flags: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                if !flags.is_empty() {
                    log_json["flags"] = json!(flags);
                }
            }
            if let Some(v) = iface.get("mtu").and_then(|v| v.as_u64()) {
                log_json["mtu"] = json!(v);
            }
            if let Some(v) = iface.get("rx_bytes").and_then(|v| v.as_u64()) {
                log_json["rx_bytes"] = json!(v);
            }
            if let Some(v) = iface.get("tx_bytes").and_then(|v| v.as_u64()) {
                log_json["tx_bytes"] = json!(v);
            }
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Network parser: Failed to convert interface {}: {}", idx + 1, e);
                }
            }
        }
    }

    // Network stats: rx_bytes, tx_bytes, network_type, wifi_network_name, subscriber_id, rat_type, metered, default_network
    if let Some(stats) = output.get("network_stats").and_then(|v| v.as_array()) {
        debug!("Network parser: Found {} network_stats entries", stats.len());
        for (idx, stat) in stats.iter().enumerate() {
            let mut log_json = json!({ "event_type": "network_stats" });
            if let Some(v) = stat.get("rx_bytes").and_then(|v| v.as_u64()) {
                log_json["rx_bytes"] = json!(v);
            }
            if let Some(v) = stat.get("tx_bytes").and_then(|v| v.as_u64()) {
                log_json["tx_bytes"] = json!(v);
            }
            if let Some(v) = stat.get("rx_packets").and_then(|v| v.as_u64()) {
                log_json["rx_packets"] = json!(v);
            }
            if let Some(v) = stat.get("tx_packets").and_then(|v| v.as_u64()) {
                log_json["tx_packets"] = json!(v);
            }
            if let Some(v) = stat.get("network_type").and_then(|v| v.as_str()) {
                log_json["network_type"] = json!(v);
            }
            if let Some(v) = stat.get("wifi_network_name").and_then(|v| v.as_str()) {
                log_json["wifi_network_name"] = json!(v);
            }
            if let Some(v) = stat.get("subscriber_id").and_then(|v| v.as_str()) {
                log_json["subscriber_id"] = json!(v);
            }
            if let Some(v) = stat.get("rat_type").and_then(|v| v.as_str()) {
                log_json["rat_type"] = json!(v);
            }
            if let Some(v) = stat.get("metered").and_then(|v| v.as_bool()) {
                log_json["metered"] = json!(v);
            }
            if let Some(v) = stat.get("default_network").and_then(|v| v.as_bool()) {
                log_json["default_network"] = json!(v);
            }
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Network parser: Failed to convert network_stat {}: {}", idx + 1, e);
                }
            }
        }
    }

    // WiFi scanner: saved_networks (array of SSIDs), scan_results (section -> networks), scan_events
    if let Some(wifi) = output.get("wifi_scanner") {
        if let Some(saved) = wifi.get("saved_networks").and_then(|v| v.as_array()) {
            for (idx, v) in saved.iter().enumerate() {
                let ssid = v.as_str().unwrap_or("");
                let log_json = json!({
                    "event_type": "wifi_saved_network",
                    "ssid": ssid
                });
                match json_to_log_entry(log_json) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        conversion_errors += 1;
                        warn!("Network parser: Failed to convert saved_network {}: {}", idx + 1, e);
                    }
                }
            }
        }
        if let Some(scan_results) = wifi.get("scan_results").and_then(|v| v.as_object()) {
            for (section_name, networks_value) in scan_results {
                if let Some(networks) = networks_value.as_array() {
                    for (idx, net) in networks.iter().enumerate() {
                        let mut log_json = json!({
                            "event_type": "wifi_scan_result",
                            "scan_section": section_name
                        });
                        if let Some(v) = net.get("bssid").and_then(|v| v.as_str()) {
                            log_json["bssid"] = json!(v);
                        }
                        if let Some(v) = net.get("frequency").and_then(|v| v.as_u64()) {
                            log_json["frequency"] = json!(v);
                        }
                        if let Some(v) = net.get("rssi").and_then(|v| v.as_i64()) {
                            log_json["rssi"] = json!(v);
                        }
                        if let Some(v) = net.get("age").and_then(|v| v.as_str()) {
                            log_json["age"] = json!(v);
                        }
                        if let Some(v) = net.get("ssid").and_then(|v| v.as_str()) {
                            log_json["ssid"] = json!(v);
                        }
                        if let Some(arr) = net.get("security").and_then(|v| v.as_array()) {
                            let sec: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                            if !sec.is_empty() {
                                log_json["security"] = json!(sec);
                            }
                        }
                        match json_to_log_entry(log_json) {
                            Ok(entry) => entries.push(entry),
                            Err(e) => {
                                conversion_errors += 1;
                                warn!("Network parser: Failed to convert scan_result {} in {}: {}", idx + 1, section_name, e);
                            }
                        }
                    }
                }
            }
        }
        if let Some(events) = wifi.get("scan_events").and_then(|v| v.as_array()) {
            for (idx, ev) in events.iter().enumerate() {
                let mut log_json = json!({ "event_type": "wifi_scan_event" });
                if let Some(v) = ev.get("timestamp").and_then(|v| v.as_str()) {
                    log_json["timestamp"] = json!(v);
                }
                if let Some(v) = ev.get("event_type").and_then(|v| v.as_str()) {
                    log_json["scan_event_type"] = json!(v);
                }
                if let Some(v) = ev.get("uid").and_then(|v| v.as_u64()) {
                    log_json["uid"] = json!(v);
                }
                if let Some(v) = ev.get("package").and_then(|v| v.as_str()) {
                    log_json["package"] = json!(v);
                }
                if let Some(v) = ev.get("attribution_tag").and_then(|v| v.as_str()) {
                    log_json["attribution_tag"] = json!(v);
                }
                if ev.get("work_source").is_some() {
                    log_json["work_source"] = ev.get("work_source").unwrap().clone();
                }
                match json_to_log_entry(log_json) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        conversion_errors += 1;
                        warn!("Network parser: Failed to convert scan_event {}: {}", idx + 1, e);
                    }
                }
            }
        }
    }

    debug!(
        "Network parser: Extracted {} total entries ({} conversion errors)",
        entries.len(),
        conversion_errors
    );

    if entries.is_empty() {
        debug!("Network parser: No log entries extracted");
        None
    } else {
        Some(entries)
    }
}

/// Extracts log entries from CrashParser output
fn extract_crash_entries(output: &Value) -> Option<Vec<LogEntry>> {
    let mut entries = Vec::new();
    let mut conversion_errors = 0;
    let mut tombstone_count = 0;
    let mut anr_file_count = 0;
    let mut anr_trace_count = 0;
    
    // Crash parser returns an object with "tombstones", "anr_files", "anr_trace"
    if !output.is_object() {
        warn!("Crash parser: Output is not an object, cannot extract log entries");
        return None;
    }
    
    // Extract tombstones
    if let Some(tombstones) = output["tombstones"].as_array() {
        tombstone_count = tombstones.len();
        debug!("Crash parser: Found {} tombstones", tombstone_count);
        
        for (idx, tombstone) in tombstones.iter().enumerate() {
            let mut log_json = json!({
                "event_type": "native_crash",
                "crash_type": "tombstone"
            });
            
            // Copy tombstone fields
            if let Some(pid) = tombstone["pid"].as_u64() {
                log_json["pid"] = json!(pid);
            }
            if let Some(tid) = tombstone["tid"].as_u64() {
                log_json["tid"] = json!(tid);
            }
            if let Some(uid) = tombstone["uid"].as_u64() {
                log_json["uid"] = json!(uid);
            }
            if let Some(process) = tombstone["process_name"].as_str() {
                log_json["process_name"] = json!(process);
            }
            if let Some(signal) = tombstone["signal"].as_str() {
                log_json["signal"] = json!(signal);
            }
            if let Some(code) = tombstone["code"].as_str() {
                log_json["code"] = json!(code);
            }
            if let Some(fault_addr) = tombstone["fault_addr"].as_str() {
                log_json["fault_addr"] = json!(fault_addr);
            }
            if let Some(timestamp) = tombstone["timestamp"].as_str() {
                log_json["timestamp"] = json!(timestamp);
            }
            if let Some(abort_msg) = tombstone["abort_message"].as_str() {
                if !abort_msg.is_empty() {
                    log_json["abort_message"] = json!(abort_msg);
                }
            }
            
            // Add backtrace frame count
            if let Some(backtrace) = tombstone["backtrace"].as_array() {
                log_json["backtrace_frames"] = json!(backtrace.len());
            }
            
            match json_to_log_entry(log_json.clone()) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Crash parser: Failed to convert tombstone {}: {}. Tombstone: {:?}", idx + 1, e, tombstone);
                }
            }
            
            // Emit one log entry per backtrace frame so Sigma rules can match on library, function, build_id, etc.
            if let Some(backtrace) = tombstone["backtrace"].as_array() {
                for (frame_idx, frame) in backtrace.iter().enumerate() {
                    let mut frame_log = log_json.clone();
                    frame_log["event_type"] = json!("tombstone_backtrace");
                    frame_log["backtrace_frame_index"] = json!(frame_idx);
                    if let Some(v) = frame.get("frame").and_then(|v| v.as_i64()) {
                        frame_log["frame"] = json!(v);
                    }
                    if let Some(v) = frame.get("pc").and_then(|v| v.as_str()) {
                        frame_log["pc"] = json!(v);
                    }
                    if let Some(v) = frame.get("library").and_then(|v| v.as_str()) {
                        frame_log["library"] = json!(v);
                    }
                    if let Some(v) = frame.get("function").and_then(|v| v.as_str()) {
                        frame_log["function"] = json!(v);
                    }
                    if let Some(v) = frame.get("offset").and_then(|v| v.as_str()) {
                        frame_log["offset"] = json!(v);
                    }
                    if let Some(v) = frame.get("build_id").and_then(|v| v.as_str()) {
                        frame_log["build_id"] = json!(v);
                    }
                    if let Some(v) = frame.get("raw_line").and_then(|v| v.as_str()) {
                        frame_log["raw_line"] = json!(v);
                    }
                    match json_to_log_entry(frame_log) {
                        Ok(entry) => entries.push(entry),
                        Err(e) => {
                            conversion_errors += 1;
                            warn!("Crash parser: Failed to convert backtrace frame {} of tombstone {}: {}", frame_idx, idx + 1, e);
                        }
                    }
                }
            }
        }
    }
    
    // Extract ANR files
    if let Some(anr_files) = output.get("anr_files") {
        if let Some(files) = anr_files["files"].as_array() {
            anr_file_count = files.len();
            debug!("Crash parser: Found {} ANR files", anr_file_count);
            
            for (idx, anr_file) in files.iter().enumerate() {
                let mut log_json = json!({
                    "event_type": "anr_file",
                    "crash_type": "anr"
                });
                
                if let Some(filename) = anr_file["filename"].as_str() {
                    log_json["filename"] = json!(filename);
                }
                if let Some(size) = anr_file["size"].as_u64() {
                    log_json["size"] = json!(size);
                }
                if let Some(timestamp) = anr_file["timestamp"].as_str() {
                    log_json["timestamp"] = json!(timestamp);
                }
                if let Some(owner) = anr_file["owner"].as_str() {
                    log_json["owner"] = json!(owner);
                }
                
                match json_to_log_entry(log_json) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        conversion_errors += 1;
                        warn!("Crash parser: Failed to convert ANR file {}: {}. File: {:?}", idx + 1, e, anr_file);
                    }
                }
            }
        }
    }
    
    // Extract ANR trace
    if let Some(anr_trace) = output.get("anr_trace") {
        if let Some(threads) = anr_trace["threads"].as_array() {
            anr_trace_count = threads.len();
            debug!("Crash parser: Found ANR trace with {} threads", anr_trace_count);
            
            let mut log_json = json!({
                "event_type": "anr_trace",
                "crash_type": "anr",
                "thread_count": threads.len()
            });
            
            // Extract process info
            if let Some(process_info) = anr_trace["process_info"].as_object() {
                if let Some(pid) = process_info.get("pid").and_then(|v| v.as_str()) {
                    log_json["pid"] = json!(pid);
                }
                if let Some(cmd) = process_info.get("cmd_line").and_then(|v| v.as_str()) {
                    log_json["cmd_line"] = json!(cmd);
                }
            }
            
            // Extract header info (e.g., subject)
            if let Some(header) = anr_trace["header"].as_object() {
                if let Some(subject) = header.get("subject").and_then(|v| v.as_str()) {
                    log_json["subject"] = json!(subject);
                }
            }
            
            match json_to_log_entry(log_json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    conversion_errors += 1;
                    warn!("Crash parser: Failed to convert ANR trace: {}. Trace: {:?}", e, anr_trace);
                }
            }
        }
    }
    
    debug!("Crash parser: Extracted {} total entries ({} tombstones, {} ANR files, {} ANR traces, {} conversion errors)", 
        entries.len(), tombstone_count, anr_file_count, if anr_trace_count > 0 { 1 } else { 0 }, conversion_errors);
    
    if entries.is_empty() {
        debug!("Crash parser: No log entries extracted");
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
    fn test_extract_package_entries_with_initiating_package() {
        // Test that initiatingPackageName, originatingPackageName, and installerPackageName are preserved
        let output = json!([
            {
                "install_logs": [
                    {
                        "timestamp": "2025-11-09 09:32:45.123",
                        "event_type": "START_INSTALL",
                        "pkg": "com.example.malware",
                        "initiatingPackageName": "com.google.android.packageinstaller",
                        "originatingPackageName": "com.sec.android.app.sbrowser",
                        "installerPackageName": "com.android.vending"
                    }
                ]
            }
        ]);
        
        let entries = extract_package_entries(&output).unwrap();
        assert_eq!(entries.len(), 1);
        
        // Verify the entry contains all the package name fields
        let entry = &entries[0];
        let entry_json = serde_json::to_value(entry).unwrap();
        
        assert_eq!(entry_json["pkg"], json!("com.example.malware"));
        assert_eq!(entry_json["initiatingPackageName"], json!("com.google.android.packageinstaller"));
        assert_eq!(entry_json["originatingPackageName"], json!("com.sec.android.app.sbrowser"));
        assert_eq!(entry_json["installerPackageName"], json!("com.android.vending"));
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

    #[test]
    fn test_extract_battery_entries() {
        // Test new Battery parser format with "apps" and "battery_history"
        let output = json!({
            "apps": [
                {
                    "uid": 1010123,
                    "package_name": "\"com.example.app\"",
                    "cpu_user_time_ms": 1000,
                    "cpu_system_time_ms": 500,
                    "foreground_service_time_ms": 60000,
                    "total_network_bytes": 1024000,
                    "total_wakelock_time_ms": 5000,
                    "total_job_count": 10,
                    "wakelocks": [],
                    "background_jobs": []
                },
                {
                    "uid": 1010124,
                    "package_name": "\"com.another.app\"",
                    "cpu_user_time_ms": 2000,
                    "cpu_system_time_ms": 800,
                    "foreground_service_time_ms": 0,
                    "total_network_bytes": 5000,
                    "total_wakelock_time_ms": 100,
                    "total_job_count": 2,
                    "wakelocks": [],
                    "background_jobs": []
                }
            ],
            "battery_history": [
                {
                    "timestamp": "2025-09-15 18:38:21",
                    "status": "charging",
                    "volt": 4200,
                    "temp": 250,
                    "charge": 85
                }
            ],
            "version_info": {
                "sdk_version": 34,
                "build_number_1": "12345"
            }
        });
        
        let entries = extract_battery_entries(&output).unwrap();
        // Should extract 2 apps + 1 history entry = 3 entries
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_extract_crash_entries() {
        // Test Crash parser format with tombstones, anr_files, and anr_trace
        let output = json!({
            "tombstones": [
                {
                    "pid": 1234,
                    "tid": 1235,
                    "uid": 10100,
                    "process_name": "com.test.app",
                    "signal": "SIGSEGV",
                    "code": "SEGV_MAPERR",
                    "fault_addr": "0x0000000000000000",
                    "timestamp": "2025-11-08 17:54:03",
                    "backtrace": [
                        {"frame": 0, "pc": "1234", "library": "/system/lib64/test.so"}
                    ]
                },
                {
                    "pid": 5678,
                    "tid": 5679,
                    "uid": 10200,
                    "process_name": "com.another.app",
                    "signal": "SIGABRT",
                    "code": "SI_QUEUE",
                    "fault_addr": "0x0",
                    "abort_message": "Test abort",
                    "backtrace": []
                }
            ],
            "anr_files": {
                "files": [
                    {
                        "filename": "anr_2025-09-15-18-38-21-363",
                        "size": 239325,
                        "timestamp": "2025-09-15 18:38",
                        "owner": "system",
                        "group": "system",
                        "permissions": "-rw-------"
                    }
                ],
                "total_size": 236
            },
            "anr_trace": {
                "header": {
                    "subject": "ANR in com.example.app"
                },
                "process_info": {
                    "pid": "12345",
                    "cmd_line": "com.example.app"
                },
                "threads": [
                    {"name": "main", "tid": 1, "priority": 5},
                    {"name": "worker", "tid": 2, "priority": 5}
                ]
            }
        });
        
        let entries = extract_crash_entries(&output).unwrap();
        // Should extract 2 tombstones + 1 backtrace frame (first tombstone has 1 frame) + 1 ANR file + 1 ANR trace = 5 entries
        assert_eq!(entries.len(), 5);
        // One entry should be a tombstone_backtrace with library
        let backtrace_entries: Vec<_> = entries.iter().filter(|e| {
            e.fields.get("event_type").and_then(|v: &serde_json::Value| v.as_str()) == Some("tombstone_backtrace")
        }).collect();
        assert_eq!(backtrace_entries.len(), 1);
        assert_eq!(backtrace_entries[0].fields.get("library").and_then(|v: &serde_json::Value| v.as_str()), Some("/system/lib64/test.so"));
    }

    #[test]
    fn test_extract_bluetooth_entries() {
        let output = json!({
            "devices": [
                {
                    "mac_address": "a0:0c:e2:1e:53:25",
                    "masked_address": "XX:XX:XX:XX:53:25",
                    "name": "OpenFit 2+ by Shokz",
                    "transport_type": "DUAL",
                    "device_class": "0x240404",
                    "services": ["SPP", "HSP", "AudioSink"],
                    "connected": false,
                    "manufacturer": 688,
                    "device_type": 3
                },
                {
                    "masked_address": "XX:XX:XX:XX:91:F7",
                    "name": "Instinct 3 - 45mm Tac",
                    "transport_type": "LE",
                    "device_class": "0x000704",
                    "services": [],
                    "connected": true
                }
            ]
        });
        let entries = extract_bluetooth_entries(&output).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].fields.get("event_type").and_then(|v: &serde_json::Value| v.as_str()),
            Some("bluetooth_device")
        );
        assert_eq!(
            entries[0].fields.get("name").and_then(|v: &serde_json::Value| v.as_str()),
            Some("OpenFit 2+ by Shokz")
        );
        assert_eq!(
            entries[1].fields.get("connected").and_then(|v: &serde_json::Value| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn test_extract_network_entries() {
        let output = json!({
            "sockets": [
                {
                    "protocol": "tcp",
                    "local_address": "127.0.0.1:12345",
                    "remote_address": "10.0.0.1:443",
                    "local_ip": "127.0.0.1",
                    "local_port": 12345,
                    "remote_ip": "10.0.0.1",
                    "remote_port": 443,
                    "state": "ESTABLISHED",
                    "uid": 10100
                }
            ],
            "interfaces": [
                {
                    "name": "wlan0",
                    "ip_addresses": ["192.168.1.100"],
                    "flags": ["UP", "BROADCAST"],
                    "mtu": 1500,
                    "rx_bytes": 1000000,
                    "tx_bytes": 500000
                }
            ],
            "network_stats": [
                {
                    "rx_bytes": 2000000,
                    "tx_bytes": 800000,
                    "network_type": "WIFI",
                    "wifi_network_name": "MyNetwork",
                    "metered": false,
                    "default_network": true
                }
            ],
            "wifi_scanner": {
                "saved_networks": ["HomeWiFi", "Office"]
            }
        });
        let entries = extract_network_entries(&output).unwrap();
        // 1 socket + 1 interface + 1 network_stat + 2 saved_networks = 5 entries
        assert_eq!(entries.len(), 5);
        let event_types: Vec<Option<&str>> = entries
            .iter()
            .map(|e| e.fields.get("event_type").and_then(|v: &serde_json::Value| v.as_str()))
            .collect();
        assert!(event_types.contains(&Some("network_socket")));
        assert!(event_types.contains(&Some("network_interface")));
        assert!(event_types.contains(&Some("network_stats")));
        assert!(event_types.contains(&Some("wifi_saved_network")));
        assert_eq!(
            entries[0].fields.get("protocol").and_then(|v: &serde_json::Value| v.as_str()),
            Some("tcp")
        );
        assert_eq!(
            entries[1].fields.get("name").and_then(|v: &serde_json::Value| v.as_str()),
            Some("wlan0")
        );
    }
}