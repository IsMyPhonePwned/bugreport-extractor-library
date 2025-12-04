use super::Parser;
use serde_json::{json, Value};
use std::error::Error;
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
struct UsbPort {
    id: String,
    connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    power_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supported_modes: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
struct UsbDevice {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
struct UsbInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    current_functions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usb_data_unlocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_host_connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_device_connected: Option<bool>,
    
    ports: Vec<UsbPort>,
    connected_devices: Vec<UsbDevice>,
}

#[derive(PartialEq)]
enum ParserState {
    Global,
    PortManager,
    DeviceList, // Inside mDevices=[ ... ]
}

/// A parser for 'DUMP OF SERVICE usb' sections.
pub struct UsbParser;

impl Default for UsbParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Usb Parser")
    }
}

impl UsbParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(UsbParser)
    }

    fn extract_value(line: &str, key: &str) -> Option<String> {
        if let Some(idx) = line.find(key) {
            let mut value_part = &line[idx + key.len()..];
            value_part = value_part.trim_start();
            
            if let Some(stripped) = value_part.strip_prefix(':') {
                value_part = stripped;
            } else if let Some(stripped) = value_part.strip_prefix('=') {
                value_part = stripped;
            }
            
            let val = value_part.trim();
            if !val.is_empty() && val != "null" {
                return Some(val.to_string());
            }
        }
        None
    }
}

impl Parser for UsbParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        
        const START_DELIMITER: &str = "DUMP OF SERVICE usb:";
        const END_DELIMITER_PREFIX: &str = "-------------------------------------------------------------------------------";

        let mut usb_info = UsbInfo {
            current_functions: None,
            usb_data_unlocked: None,
            is_host_connected: None,
            is_device_connected: None,
            ports: Vec::new(),
            connected_devices: Vec::new(),
        };

        if let Some(start_index) = content.find(START_DELIMITER) {
            let block_content = &content[start_index..];
            let lines = block_content.lines();
            
            let mut state = ParserState::Global;
            let mut current_port: Option<UsbPort> = None;
            let mut current_device: Option<UsbDevice> = None;
            let mut last_seen_label: Option<String> = None;

            for line in lines {
                let trimmed = line.trim();
                
                // Check for end of section
                if trimmed.starts_with(END_DELIMITER_PREFIX) && !line.contains(START_DELIMITER) {
                    break;
                }
                
                // State Switching
                if trimmed.starts_with("mDevices=[") {
                    state = ParserState::DeviceList;
                    continue;
                }
                
                match state {
                    ParserState::Global | ParserState::PortManager => {
                        // --- Global Info ---
                        if trimmed.contains("CurrentFunctions") {
                             usb_info.current_functions = Self::extract_value(line, "CurrentFunctions");
                        } else if trimmed.contains("UsbDataUnlocked") {
                             usb_info.usb_data_unlocked = Self::extract_value(line, "UsbDataUnlocked").and_then(|s| s.parse().ok());
                        } else if trimmed.starts_with("IsHostConnected") {
                             usb_info.is_host_connected = Self::extract_value(line, "IsHostConnected").map(|s| s == "true");
                        } else if trimmed.starts_with("IsDeviceConnected") {
                             usb_info.is_device_connected = Self::extract_value(line, "IsDeviceConnected").map(|s| s == "true");
                        }

                        // --- AOSP Device Style (Device: /path) ---
                        if trimmed.starts_with("Device:") {
                            // If we were parsing a port, flush it
                            if let Some(port) = current_port.take() { usb_info.ports.push(port); }
                            // If we were parsing a previous AOSP device, flush it
                            if let Some(device) = current_device.take() { usb_info.connected_devices.push(device); }
                            
                            let path = Self::extract_value(line, "Device").map(|s| s.to_string());
                            current_device = Some(UsbDevice {
                                path, vid: None, pid: None, product_name: None, manufacturer: None
                            });
                        }
                        // AOSP Device Fields
                        if let Some(ref mut device) = current_device {
                             if trimmed.starts_with("mVendorId:") { device.vid = Self::extract_value(line, ":"); }
                             else if trimmed.starts_with("mProductId:") { device.pid = Self::extract_value(line, ":"); }
                             else if trimmed.starts_with("mProduct:") { device.product_name = Self::extract_value(line, ":"); }
                             else if trimmed.starts_with("mManufacturer:") { device.manufacturer = Self::extract_value(line, ":"); }
                        }

                        // --- Port Detection ---
                        // Capture potential port name (e.g. "port0:")
                        if trimmed.ends_with(':') && !trimmed.contains(' ') && !trimmed.starts_with("Device") {
                             last_seen_label = Some(trimmed.trim_end_matches(':').to_string());
                        }

                        if trimmed.starts_with("connected:") {
                             state = ParserState::PortManager;
                             if let Some(port) = current_port.take() { usb_info.ports.push(port); }
                             // Flush device if we switched from AOSP device parsing
                             if let Some(device) = current_device.take() { usb_info.connected_devices.push(device); }

                             let port_id = last_seen_label.clone().unwrap_or_else(|| "unknown_port".to_string());
                             let is_connected = Self::extract_value(line, "connected").map(|v| v == "true").unwrap_or(false);
                             
                             current_port = Some(UsbPort {
                                id: port_id,
                                connected: is_connected,
                                current_mode: None, power_role: None, data_role: None, supported_modes: None
                             });
                        }
                        
                        // Port fields
                        if let Some(ref mut port) = current_port {
                            if trimmed.starts_with("current_mode:") { port.current_mode = Self::extract_value(line, "current_mode"); }
                            else if trimmed.starts_with("power_role:") { port.power_role = Self::extract_value(line, "power_role"); }
                            else if trimmed.starts_with("data_role:") { port.data_role = Self::extract_value(line, "data_role"); }
                            else if trimmed.starts_with("supported_modes:") { port.supported_modes = Self::extract_value(line, "supported_modes"); }
                        }
                    },
                    
                    ParserState::DeviceList => {
                        if trimmed == "]" {
                            state = ParserState::Global;
                            // Flush if a device was open (unlikely in this format but safe)
                            if let Some(device) = current_device.take() { usb_info.connected_devices.push(device); }
                            continue;
                        }
                        
                        if trimmed == "{" {
                            // Start new Samsung device
                            if let Some(device) = current_device.take() { usb_info.connected_devices.push(device); }
                            current_device = Some(UsbDevice {
                                path: None, vid: None, pid: None, product_name: None, manufacturer: None
                            });
                        } else if trimmed == "}" {
                            // End Samsung device
                            if let Some(device) = current_device.take() {
                                usb_info.connected_devices.push(device);
                            }
                        }
                        
                        // Device Fields (Samsung Style: key=value)
                        if let Some(ref mut device) = current_device {
                             if trimmed.starts_with("vendor_id=") { device.vid = Self::extract_value(line, "="); }
                             else if trimmed.starts_with("product_id=") { device.pid = Self::extract_value(line, "="); }
                             else if trimmed.starts_with("product_name=") { device.product_name = Self::extract_value(line, "="); }
                             else if trimmed.starts_with("manufacturer_name=") { device.manufacturer = Self::extract_value(line, "="); }
                        }
                    }
                }
            }
            
            // Final Flush
            if let Some(port) = current_port { usb_info.ports.push(port); }
            if let Some(device) = current_device { usb_info.connected_devices.push(device); }

            // Fallback for missing ports
            if usb_info.ports.is_empty() {
                if let Some(true) = usb_info.is_device_connected {
                    usb_info.ports.push(UsbPort {
                        id: "system_status".to_string(), connected: true, current_mode: Some("peripheral".to_string()),
                        power_role: None, data_role: None, supported_modes: None
                    });
                } else if let Some(true) = usb_info.is_host_connected {
                     usb_info.ports.push(UsbPort {
                        id: "system_status".to_string(), connected: true, current_mode: Some("host".to_string()),
                        power_role: None, data_role: None, supported_modes: None
                    });
                }
            }
        }

        Ok(json!([usb_info]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_samsung_usb_dump() {
        let data = b"
DUMP OF SERVICE usb:
USB MANAGER STATE (dumpsys usb):
  IsHostConnected :false
  IsDeviceConnected :true
  UsbHostManager:
    mDevices=[
      {
        vendor_id=4042
        product_id=32772
        product_name=Samsung Device
      }
    ]
        ";
        
        let parser = UsbParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let info = &result.as_array().unwrap()[0];

        assert_eq!(info["is_device_connected"], true);
        
        let devices = info["connected_devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["vid"], "4042");
        assert_eq!(devices[0]["product_name"], "Samsung Device");
    }
}