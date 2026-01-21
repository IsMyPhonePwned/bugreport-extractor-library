use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Represents a Bluetooth device parsed from the bug report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDevice {
    pub mac_address: Option<String>,  // Complete MAC address if available
    pub masked_address: String,       // Masked address (XX:XX:XX:XX:XX:XX)
    pub identity_address: Option<String>, // Identity address if different
    pub name: Option<String>,
    pub transport_type: Option<String>, // LE, DUAL, BR/EDR
    pub device_class: Option<String>,   // Hex value like 0x000918
    pub services: Vec<String>,         // List of services/UUIDs
    pub connected: bool,
    // Additional details from detailed sections
    pub manufacturer: Option<u32>,
    pub device_type: Option<u32>,
    pub link_type: Option<u32>,
}


/// A parser for Bluetooth-related sections in Android bug reports.
/// Parses bonded devices and connected equipment.
pub struct BluetoothParser;

impl Default for BluetoothParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Bluetooth Parser")
    }
}

impl BluetoothParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(BluetoothParser)
    }

    /// Extract Bluetooth devices from the parser's JSON output
    /// This is a helper function to convert the JSON Value to typed BluetoothDevice structs
    pub fn extract_devices_from_json(json_value: &Value) -> Result<Vec<BluetoothDevice>, Box<dyn Error + Send + Sync>> {
        let devices_array = json_value
            .get("devices")
            .and_then(|v| v.as_array())
            .ok_or("No 'devices' array found in Bluetooth JSON")?;
        
        let mut devices = Vec::new();
        for device_value in devices_array {
            let device: BluetoothDevice = serde_json::from_value(device_value.clone())?;
            devices.push(device);
        }
        
        Ok(devices)
    }

    // Parse a MAC address from various formats
    // Returns None if invalid
    fn parse_mac_address(s: &str) -> Option<String> {
        // Remove brackets if present: [a0:0c:e2:1e:53:25] -> a0:0c:e2:1e:53:25
        let cleaned = s.trim().trim_start_matches('[').trim_end_matches(']');
        
        // Check if it's a valid MAC address format (6 hex bytes separated by colons)
        let parts: Vec<&str> = cleaned.split(':').collect();
        if parts.len() == 6 {
            // Verify each part is 2 hex digits
            if parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())) {
                return Some(cleaned.to_uppercase());
            }
        }
        None
    }

    // Check if a string looks like a MAC address pattern (for extraction)
    // Handles both masked (XX:XX:XX:XX:XX:XX) and partial masked (XX:XX:XX:XX:53:25) addresses
    fn looks_like_mac_address(s: &str) -> bool {
        let parts: Vec<&str> = s.split(':').collect();
        parts.len() == 6 && parts.iter().all(|p| p.len() == 2)
    }
    
    // Parse AdapterProperties section
    // Format:
    // AdapterProperties
    //   Name: Galaxy Z Flip7
    //   Address: XX:XX:XX:XX:7F:82
    //   ConnectionState: STATE_DISCONNECTED
    //   State: ON
    //   MaxConnectedAudioDevices: 2
    //   A2dpOffloadEnabled: true
    //   Discovering: false
    //   DiscoveryEndMs: 0
    //   SarType: HEAD
    //   SarStatus: OFF
    //   SarHistory: Yes
    fn parse_adapter_properties(section: &str) -> Map<String, Value> {
        let mut properties = Map::new();
        const ADAPTER_PROPERTIES_MARKER: &str = "AdapterProperties";
        
        if let Some(adapter_start) = section.find(ADAPTER_PROPERTIES_MARKER) {
            let adapter_section = &section[adapter_start..];
            let lines: Vec<&str> = adapter_section.lines().collect();
            
            // Skip the "AdapterProperties" line and parse properties
            for line in lines.iter().skip(1) {
                let trimmed = line.trim();
                
                // Stop at "Bonded devices:" or empty line followed by a section header
                if trimmed.is_empty() || trimmed.starts_with("Bonded devices:") {
                    break;
                }
                
                // Parse key: value pairs
                if let Some((key, value)) = trimmed.split_once(':') {
                    let key = key.trim();
                    let value = value.trim();
                    
                    // Try to parse as boolean
                    if value == "true" {
                        properties.insert(key.to_string(), json!(true));
                    } else if value == "false" {
                        properties.insert(key.to_string(), json!(false));
                    } else {
                        // Try to parse as number
                        if let Ok(num) = value.parse::<i64>() {
                            properties.insert(key.to_string(), json!(num));
                        } else if let Ok(num) = value.parse::<f64>() {
                            properties.insert(key.to_string(), json!(num));
                        } else {
                            // Keep as string
                            properties.insert(key.to_string(), json!(value));
                        }
                    }
                }
            }
        }
        
        properties
    }
}

impl Parser for BluetoothParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut result = Map::new();
        let mut devices: Vec<BluetoothDevice> = Vec::new();
        
        // Find the "DUMP OF SERVICE bluetooth_manager:" section
        const SERVICE_START: &str = "DUMP OF SERVICE bluetooth_manager:";
        
        let bluetooth_section = if let Some(start_index) = content.find(SERVICE_START) {
            let section_content = &content[start_index..];
            // Find the end of the section (duration line for bluetooth_manager)
            // Format: "--------- 0.810s was the duration of dumpsys bluetooth_manager, ending at: ..."
            let lines: Vec<&str> = section_content.lines().collect();
            let mut end_line_index = None;
            
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("---------") && 
                   trimmed.contains("duration of dumpsys bluetooth_manager") {
                    end_line_index = Some(i);
                    break;
                }
            }
            
            if let Some(end_line) = end_line_index {
                lines[..end_line].join("\n")
            } else {
                // If no end marker found, use all content from start
                section_content.to_string()
            }
        } else {
            // No bluetooth_manager section found
            return Ok(json!(result));
        };
        
        // Parse AdapterProperties section
        let adapter_properties = Self::parse_adapter_properties(&bluetooth_section);
        if !adapter_properties.is_empty() {
            result.insert("adapter_properties".to_string(), json!(adapter_properties));
        }
        
        // First, collect all complete MAC addresses from detailed sections within the bluetooth_manager section
        // Format: [a0:0c:e2:1e:53:25] followed by device details
        let mut mac_to_details: HashMap<String, Map<String, Value>> = HashMap::new();
        
        // Parse detailed device information sections
        // Format: [a0:0c:e2:1e:53:25]\nName = ...\nManufacturer = ...
        let lines: Vec<&str> = bluetooth_section.lines().collect();
        let mut current_mac: Option<String> = None;
        let mut current_details: Map<String, Value> = Map::new();
        
        for line in lines.iter() {
            let trimmed = line.trim();
            
            // Check if this is a MAC address line
            if trimmed.starts_with('[') && trimmed.contains(']') {
                // Save previous device details
                if let Some(ref mac) = current_mac {
                    mac_to_details.insert(mac.clone(), current_details.clone());
                }
                
                // Start new device
                if let Some(bracket_end) = trimmed.find(']') {
                    let mac_str = &trimmed[1..bracket_end];
                    if let Some(mac) = Self::parse_mac_address(&format!("[{}]", mac_str)) {
                        current_mac = Some(mac);
                        current_details = Map::new();
                    }
                }
            } else if current_mac.is_some() {
                // Parse key=value pairs for current device
                if let Some((key, value)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    current_details.insert(key.to_string(), json!(value));
                }
            }
        }
        
        // Save last device
        if let Some(ref mac) = current_mac {
            mac_to_details.insert(mac.clone(), current_details.clone());
        }
        
        // Parse "Bonded devices:" section within the bluetooth_manager section
        const BONDED_DEVICES_MARKER: &str = "Bonded devices:";
        if let Some(bonded_start) = bluetooth_section.find(BONDED_DEVICES_MARKER) {
            let bonded_section = &bluetooth_section[bonded_start..];
            let bonded_lines: Vec<&str> = bonded_section
                .lines()
                .skip(1) // Skip the "Bonded devices:" line
                .take_while(|line| {
                    let trimmed = line.trim();
                    !trimmed.is_empty() && 
                    !trimmed.starts_with("Devices in DB:") &&
                    !trimmed.starts_with("ScanMode:")
                })
                .collect();
            
            for line in bonded_lines {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                
                // Check if device is connected
                let connected = trimmed.starts_with("(Connected)");
                let line_content = if connected {
                    &trimmed[11..].trim() // Skip "(Connected) " and trim
                } else {
                    trimmed
                };
                
                // Parse the line format:
                // XX:XX:XX:XX:C3:C9 => XX:XX:XX:XX:D9:BF [  LE  ][ 0x000918 ] Oura 2016092514055254 (No uuid)
                // or: XX:XX:XX:XX:34:E6 [ DUAL ][ 0x260408 ] MY_CAR (SPP,AudioSink,Avrcp,...)
                
                let mut masked_addr = String::new();
                let mut identity_addr = None;
                let mut transport_type = None;
                let mut device_class = None;
                let mut name = None;
                let mut services = Vec::new();
                
                // Extract masked address (first MAC-like pattern)
                // Format can be: "XX:XX:XX:XX:C3:C9 => XX:XX:XX:XX:D9:BF" or "XX:XX:XX:XX:34:E6"
                let parts: Vec<&str> = line_content.split_whitespace().collect();
                for part in &parts {
                    if Self::looks_like_mac_address(part) {
                        if masked_addr.is_empty() {
                            masked_addr = part.to_string();
                        } else {
                            // This is the identity address (after =>)
                            identity_addr = Some(part.to_string());
                            break;
                        }
                    }
                }
                
                // Extract transport type: [  LE  ], [ DUAL ], [BR/EDR]
                if let Some(transport_start) = line_content.find('[') {
                    if let Some(transport_end) = line_content[transport_start + 1..].find(']') {
                        let transport_str = line_content[transport_start + 1..transport_start + 1 + transport_end].trim();
                        if !transport_str.is_empty() && !transport_str.starts_with("0x") {
                            transport_type = Some(transport_str.to_string());
                        }
                    }
                }
                
                // Extract device class: [ 0x000918 ]
                if let Some(class_start) = line_content.find("[ 0x") {
                    if let Some(class_end) = line_content[class_start + 1..].find(']') {
                        let class_str = &line_content[class_start + 2..class_start + 1 + class_end].trim();
                        device_class = Some(class_str.to_string());
                    }
                }
                
                // Extract name (text between device class and services)
                // Find the last bracket before services (in parentheses)
                if let Some(services_start) = line_content.find('(') {
                    let name_part = &line_content[..services_start].trim();
                    // The name is typically after the device class bracket
                    if let Some(last_bracket) = name_part.rfind(']') {
                        let name_candidate = &name_part[last_bracket + 1..].trim();
                        if !name_candidate.is_empty() {
                            name = Some(name_candidate.to_string());
                        }
                    }
                } else {
                    // No services, name is after device class
                    if let Some(last_bracket) = line_content.rfind(']') {
                        let name_candidate = &line_content[last_bracket + 1..].trim();
                        if !name_candidate.is_empty() {
                            name = Some(name_candidate.to_string());
                        }
                    }
                }
                
                // Extract services (in parentheses)
                if let Some(services_start) = line_content.find('(') {
                    if let Some(services_end) = line_content[services_start + 1..].find(')') {
                        let services_str = &line_content[services_start + 1..services_start + 1 + services_end];
                        services = services_str.split(',').map(|s| s.trim().to_string()).collect();
                    }
                }
                
                // Try to find complete MAC address by matching masked address pattern
                // We'll match by device name and other characteristics
                let mut complete_mac = None;
                
                // Try to match by name in the detailed sections
                if let Some(ref device_name) = name {
                    for (mac, details) in &mac_to_details {
                        if let Some(Value::String(detail_name)) = details.get("Name") {
                            if detail_name.trim() == device_name.trim() {
                                complete_mac = Some(mac.clone());
                                break;
                            }
                        }
                    }
                }
                
                // If not found by name, try to match by device class
                if complete_mac.is_none() {
                    if let Some(ref class) = device_class {
                        for (mac, details) in &mac_to_details {
                            if let Some(Value::String(detail_class)) = details.get("DevClass") {
                                // Convert hex to compare
                                if let (Ok(class_val), Ok(detail_val)) = (
                                    u32::from_str_radix(class.trim_start_matches("0x"), 16),
                                    u32::from_str_radix(detail_class.trim(), 10)
                                ) {
                                    if class_val == detail_val {
                                        complete_mac = Some(mac.clone());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                devices.push(BluetoothDevice {
                    mac_address: complete_mac,
                    masked_address: masked_addr,
                    identity_address: identity_addr,
                    name,
                    transport_type,
                    device_class,
                    services,
                    connected,
                    manufacturer: None,
                    device_type: None,
                    link_type: None,
                });
            }
        }
        
        // Enrich devices with details from mac_to_details
        for device in &mut devices {
            if let Some(ref mac) = device.mac_address {
                if let Some(details) = mac_to_details.get(mac) {
                    if let Some(Value::String(manufacturer)) = details.get("Manufacturer") {
                        device.manufacturer = manufacturer.parse().ok();
                    }
                    if let Some(Value::String(dev_type)) = details.get("DevType") {
                        device.device_type = dev_type.parse().ok();
                    }
                    if let Some(Value::String(link_type)) = details.get("LinkType") {
                        device.link_type = link_type.parse().ok();
                    }
                }
            }
        }
        
        // Convert to JSON
        if !devices.is_empty() {
            let devices_json: Vec<Value> = devices.iter()
                .map(|d| serde_json::to_value(d).unwrap_or_else(|_| json!({})))
                .collect();
            result.insert("devices".to_string(), json!(devices_json));
        }
        
        Ok(json!(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_bluetooth_bonded_devices() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE bluetooth_manager:
Bluetooth Status
  enabled: true
  state: ON

AdapterProperties
  Name: Galaxy Z Flip7
  Address: XX:XX:XX:XX:7F:82
  ConnectionState: STATE_DISCONNECTED
  State: ON
  MaxConnectedAudioDevices: 2
  A2dpOffloadEnabled: true
  Discovering: false
  DiscoveryEndMs: 0
  SarType: HEAD
  SarStatus: OFF
  SarHistory: Yes
  Bonded devices:
    (Connected) XX:XX:XX:XX:C3:C9 => XX:XX:XX:XX:D9:BF [  LE  ][ 0x000918 ] Oura 2016092514055254 (No uuid)
                XX:XX:XX:XX:34:E6 [ DUAL ][ 0x260408 ] MY_CAR (SPP,AudioSink,Avrcp,PANU,NAP,Handsfree,MNS,4de17a00-52cb-11e6-bdf4-0800200c9a66)
                XX:XX:XX:XX:53:25 [ DUAL ][ 0x240404 ] OpenFit 2+ by Shokz (SPP,HSP,AudioSink,Avrcp,Handsfree,66666666-6666-6666-6666-666666666666)
    (Connected) XX:XX:XX:XX:91:F7 [  LE  ][ 0x000704 ] Instinct 3 - 45mm Tac (00000000-0000-0000-0000-000000000000)

[a0:0c:e2:1e:53:25]
Name = OpenFit 2+ by Shokz
DevClass = 2360324
DevType = 3
Manufacturer = 688

[00:92:a5:a1:34:e6]
Name = MY_CAR
DevClass = 2491400
DevType = 2
Manufacturer = 305
--------- 0.810s was the duration of dumpsys bluetooth_manager, ending at: 2026-01-21 11:08:15
        ";
        
        let parser = BluetoothParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Check adapter properties
        assert!(result["adapter_properties"].is_object());
        let adapter = result["adapter_properties"].as_object().unwrap();
        assert_eq!(adapter["Name"], "Galaxy Z Flip7");
        assert_eq!(adapter["Address"], "XX:XX:XX:XX:7F:82");
        assert_eq!(adapter["ConnectionState"], "STATE_DISCONNECTED");
        assert_eq!(adapter["State"], "ON");
        assert_eq!(adapter["MaxConnectedAudioDevices"], 2);
        assert_eq!(adapter["A2dpOffloadEnabled"], true);
        assert_eq!(adapter["Discovering"], false);
        assert_eq!(adapter["DiscoveryEndMs"], 0);
        assert_eq!(adapter["SarType"], "HEAD");
        assert_eq!(adapter["SarStatus"], "OFF");
        assert_eq!(adapter["SarHistory"], "Yes");
        
        assert!(result["devices"].is_array());
        let devices = result["devices"].as_array().unwrap();
        assert!(devices.len() >= 4);
        
        // Find OpenFit device
        let openfit = devices.iter().find(|d| {
            d["name"].as_str() == Some("OpenFit 2+ by Shokz")
        }).unwrap();
        assert_eq!(openfit["mac_address"], "A0:0C:E2:1E:53:25");
        assert_eq!(openfit["masked_address"], "XX:XX:XX:XX:53:25");
        assert_eq!(openfit["transport_type"], "DUAL");
        assert_eq!(openfit["connected"], false);
        assert_eq!(openfit["manufacturer"], 688);
        
        // Find MY_CAR device
        let mycar = devices.iter().find(|d| {
            d["name"].as_str() == Some("MY_CAR")
        }).unwrap();
        assert_eq!(mycar["mac_address"], "00:92:A5:A1:34:E6");
        assert_eq!(mycar["masked_address"], "XX:XX:XX:XX:34:E6");
        assert_eq!(mycar["transport_type"], "DUAL");
        assert_eq!(mycar["connected"], false);
        
        // Find Oura device (connected)
        let oura = devices.iter().find(|d| {
            d["name"].as_str() == Some("Oura 2016092514055254")
        }).unwrap();
        assert_eq!(oura["connected"], true);
        assert_eq!(oura["transport_type"], "LE");
    }
}
