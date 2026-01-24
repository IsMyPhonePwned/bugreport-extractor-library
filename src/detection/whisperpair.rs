// WhisperPair Vulnerability Detector
// Detects if vulnerable Bluetooth devices from the WhisperPair vulnerability list are present
// Reference: https://whisperpair.eu/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::parsers::bluetooth_parser::BluetoothDevice;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableDevice {
    pub name: String,
    pub manufacturer: String,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub vulnerable: Option<bool>,
    #[serde(default)]
    pub fhn: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperPairDetection {
    pub device_name: String,
    pub device_manufacturer: Option<String>,
    pub vulnerable_device: VulnerableDevice,
    pub mac_address: Option<String>,
    pub masked_address: Option<String>,
    pub connected: bool,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperPairDetectionResult {
    pub detected_devices: Vec<WhisperPairDetection>,
    pub total_detected: usize,
    pub has_vulnerable_devices: bool,
}

pub struct WhisperPairDetector {
    vulnerable_devices: Vec<VulnerableDevice>,
    // Index for fast lookup by name
    name_index: HashMap<String, Vec<usize>>,
    // Index for fast lookup by manufacturer
    #[allow(dead_code)]
    manufacturer_index: HashMap<String, Vec<usize>>,
}

impl WhisperPairDetector {
    /// Create a new detector with the default vulnerable devices list
    pub fn new() -> Self {
        // Load from embedded JSON file
        const DEVICES_JSON: &str = include_str!("../../data/whisperpair_devices.json");
        Self::from_json(DEVICES_JSON).unwrap_or_else(|e| {
            panic!("Failed to load WhisperPair devices list: {}. This should not happen if the JSON file is valid.", e);
        })
    }

    /// Create a detector from a JSON string
    pub fn from_json(json_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try to parse as JSON array
        let devices: Vec<VulnerableDevice> = serde_json::from_str(json_str)?;
        Ok(Self::from_devices_list(&devices))
    }

    /// Create a detector from a list of vulnerable devices
    pub fn from_devices_list(devices: &[VulnerableDevice]) -> Self {
        let mut name_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut manufacturer_index: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, device) in devices.iter().enumerate() {
            // Index by name (case-insensitive)
            let name_lower = device.name.to_lowercase();
            name_index.entry(name_lower).or_insert_with(Vec::new).push(idx);

            // Index by manufacturer (case-insensitive)
            let mfr_lower = device.manufacturer.to_lowercase();
            manufacturer_index.entry(mfr_lower).or_insert_with(Vec::new).push(idx);
        }

        Self {
            vulnerable_devices: devices.to_vec(),
            name_index,
            manufacturer_index,
        }
    }

    /// Normalize a device name for comparison (remove extra spaces, lowercase)
    fn normalize_name(name: &str) -> String {
        name.trim().to_lowercase()
    }

    /// Check if a device name matches a vulnerable device name
    fn name_matches(&self, device_name: &str) -> Option<&VulnerableDevice> {
        let normalized = Self::normalize_name(device_name);
        
        // Exact match
        if let Some(indices) = self.name_index.get(&normalized) {
            if let Some(&idx) = indices.first() {
                return Some(&self.vulnerable_devices[idx]);
            }
        }

        // Partial match (device name contains vulnerable device name or vice versa)
        for (vuln_name, indices) in &self.name_index {
            if normalized.contains(vuln_name) || vuln_name.contains(&normalized) {
                if let Some(&idx) = indices.first() {
                    return Some(&self.vulnerable_devices[idx]);
                }
            }
        }

        None
    }

    /// Detect vulnerable devices from Bluetooth parser output (typed devices)
    pub fn detect(&self, devices: &[BluetoothDevice]) -> WhisperPairDetectionResult {
        let mut detected = Vec::new();

        for device in devices {
            // Check if this device matches a vulnerable device
            if let Some(device_name) = &device.name {
                if let Some(vulnerable_device) = self.name_matches(device_name) {
                    // Only report if vulnerable is true or not specified (default to true)
                    let is_vulnerable = vulnerable_device.vulnerable.unwrap_or(true);
                    
                    if is_vulnerable {
                        detected.push(WhisperPairDetection {
                            device_name: device_name.clone(),
                            device_manufacturer: device.manufacturer.map(|m| m.to_string()),
                            vulnerable_device: vulnerable_device.clone(),
                            mac_address: device.mac_address.clone(),
                            masked_address: Some(device.masked_address.clone()),
                            connected: device.connected,
                            severity: if vulnerable_device.fhn.unwrap_or(false) {
                                "High".to_string()
                            } else {
                                "Medium".to_string()
                            },
                        });
                    }
                }
            }
        }

        WhisperPairDetectionResult {
            total_detected: detected.len(),
            has_vulnerable_devices: !detected.is_empty(),
            detected_devices: detected,
        }
    }

    /// Detect vulnerable devices from Bluetooth parser JSON output
    /// This is a convenience method that extracts devices from JSON and calls detect()
    pub fn detect_from_json(&self, bluetooth_json: &serde_json::Value) -> Result<WhisperPairDetectionResult, Box<dyn std::error::Error + Send + Sync>> {
        let devices = crate::parsers::bluetooth_parser::BluetoothParser::extract_devices_from_json(bluetooth_json)?;
        Ok(self.detect(&devices))
    }
}

impl Default for WhisperPairDetector {
    fn default() -> Self {
        Self::new()
    }
}

// Note: The full list of vulnerable devices is embedded from data/whisperpair_devices.json
// The JSON file is included at compile time using include_str!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_vulnerable_device() {
        let detector = WhisperPairDetector::new();
        
        let devices = vec![
            BluetoothDevice {
                name: Some("WH-1000XM5".to_string()),
                manufacturer: Some(12),
                mac_address: Some("00:11:22:33:44:55".to_string()),
                masked_address: "XX:XX:XX:XX:44:55".to_string(),
                connected: true,
                identity_address: None,
                transport_type: None,
                device_class: None,
                services: Vec::new(),
                device_type: None,
                link_type: None,
            },
            BluetoothDevice {
                name: Some("Some Other Device".to_string()),
                manufacturer: Some(5),
                mac_address: Some("00:11:22:33:44:66".to_string()),
                masked_address: "XX:XX:XX:XX:44:66".to_string(),
                connected: false,
                identity_address: None,
                transport_type: None,
                device_class: None,
                services: Vec::new(),
                device_type: None,
                link_type: None,
            },
        ];

        let result = detector.detect(&devices);
        
        assert!(result.has_vulnerable_devices);
        assert_eq!(result.total_detected, 1);
        assert_eq!(result.detected_devices[0].device_name, "WH-1000XM5");
        assert_eq!(result.detected_devices[0].severity, "High");
    }

    #[test]
    fn test_no_vulnerable_devices() {
        let detector = WhisperPairDetector::new();
        
        let devices = vec![
            BluetoothDevice {
                name: Some("Some Safe Device".to_string()),
                manufacturer: Some(5),
                mac_address: Some("00:11:22:33:44:66".to_string()),
                masked_address: "XX:XX:XX:XX:44:66".to_string(),
                connected: false,
                identity_address: None,
                transport_type: None,
                device_class: None,
                services: Vec::new(),
                device_type: None,
                link_type: None,
            },
        ];

        let result = detector.detect(&devices);
        
        assert!(!result.has_vulnerable_devices);
        assert_eq!(result.total_detected, 0);
    }
}
