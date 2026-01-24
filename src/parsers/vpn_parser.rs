use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;
use serde::Serialize;
use std::collections::HashMap;
use regex::Regex;

#[derive(Serialize, Debug, Clone)]
struct VpnEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addresses: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    routes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_servers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    search_domains: Option<String>,
    raw_data: String,
}

#[derive(Serialize, Debug, Clone)]
struct NetworkProperty {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    raw_data: String,
}

pub struct VpnParser;

impl Default for VpnParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the VPN Parser")
    }
}

impl VpnParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(VpnParser)
    }

    /// Extract the SecurityControllerImpl section
    fn extract_section(content: &str) -> Option<String> {
        let start_marker = "SecurityControllerImpl:";
        let end_marker = "CRITICAL dump took";
        
        let start = content.find(start_marker)?;
        let section_start = start + start_marker.len();
        let remaining = &content[section_start..];
        
        // Find the end marker
        let end = remaining.find(end_marker)?;
        
        Some(remaining[..end].trim().to_string())
    }

    /// Parse mCurrentVpns line
    /// Format: mCurrentVpns={} or mCurrentVpns={key1=value1, key2=value2, ...}
    fn parse_current_vpns(line: &str) -> HashMap<String, VpnEntry> {
        let mut vpns = HashMap::new();
        
        // Use regex to extract content between {}
        let braces_re = Regex::new(r"mCurrentVpns=\{(.*?)\}").unwrap();
        
        if let Some(caps) = braces_re.captures(line) {
            let content = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            
            // If empty, return empty map
            if content.is_empty() {
                return vpns;
            }
            
            // Parse entries using regex - match non-comma sequences
            let entry_re = Regex::new(r"([^,]+)").unwrap();
            
            for (idx, cap) in entry_re.captures_iter(content).enumerate() {
                let entry = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                if entry.is_empty() {
                    continue;
                }
                
                // Extract key and value using regex
                let kv_re = Regex::new(r"^([^=]+)=(.*)$").unwrap();
                let key = if let Some(kv_caps) = kv_re.captures(entry) {
                    kv_caps.get(1).map(|m| m.as_str().trim().to_string())
                        .unwrap_or_else(|| format!("vpn_{}", idx))
                } else {
                    format!("vpn_{}", idx)
                };
                
                let vpn_entry = VpnEntry {
                    user_id: None,
                    package_name: None,
                    interface: None,
                    addresses: None,
                    routes: None,
                    dns_servers: None,
                    search_domains: None,
                    raw_data: entry.to_string(),
                };
                
                vpns.insert(key, vpn_entry);
            }
        }
        
        vpns
    }

    /// Parse mNetworkProperties line
    /// Format: mNetworkProperties={} or mNetworkProperties={key1=value1, key2=value2, ...}
    fn parse_network_properties(line: &str) -> HashMap<String, NetworkProperty> {
        let mut properties = HashMap::new();
        
        // Use regex to extract content between {}
        let braces_re = Regex::new(r"mNetworkProperties=\{(.*?)\}").unwrap();
        
        if let Some(caps) = braces_re.captures(line) {
            let content = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            
            // If empty, return empty map
            if content.is_empty() {
                return properties;
            }
            
            // Parse key=value pairs using regex
            // Match pairs separated by commas
            let kv_re = Regex::new(r"([^,=]+)=([^,]+)").unwrap();
            
            for cap in kv_re.captures_iter(content) {
                let key = cap.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                let value = cap.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                
                if !key.is_empty() {
                    let raw_data = format!("{}={}", key, value);
                    properties.insert(key, NetworkProperty {
                        value: Some(value),
                        raw_data,
                    });
                }
            }
            
            // Also handle entries without equals sign (key only)
            // Use regex to find all comma-separated parts, then filter for those without '='
            let all_parts_re = Regex::new(r"([^,]+)").unwrap();
            for cap in all_parts_re.captures_iter(content) {
                if let Some(part_match) = cap.get(1) {
                    let part = part_match.as_str().trim();
                    // If it doesn't contain '=' and wasn't already added by kv_re, it's a key-only entry
                    if !part.is_empty() && !part.contains('=') && !properties.contains_key(part) {
                        properties.insert(part.to_string(), NetworkProperty {
                            value: None,
                            raw_data: part.to_string(),
                        });
                    }
                }
            }
        }
        
        properties
    }
}

impl Parser for VpnParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        
        // Extract the SecurityControllerImpl section
        let section = match Self::extract_section(&content) {
            Some(s) => s,
            None => {
                // Return empty result if section not found
                return Ok(json!({
                    "current_vpns": {},
                    "network_properties": {}
                }));
            }
        };
        
        let mut current_vpns = HashMap::new();
        let mut network_properties = HashMap::new();
        
        // Parse each line in the section
        for line in section.lines() {
            let trimmed = line.trim();
            
            if trimmed.starts_with("mCurrentVpns") {
                current_vpns = Self::parse_current_vpns(trimmed);
            } else if trimmed.starts_with("mNetworkProperties") {
                network_properties = Self::parse_network_properties(trimmed);
            }
        }
        
        // Build result as a map with top-level fields
        let mut result_map = Map::new();
        
        // Convert current_vpns HashMap to JSON
        let mut vpns_map = Map::new();
        for (key, vpn_entry) in current_vpns {
            vpns_map.insert(key, json!(vpn_entry));
        }
        result_map.insert("current_vpns".to_string(), json!(vpns_map));
        
        // Convert network_properties HashMap to JSON
        let mut props_map = Map::new();
        for (key, prop) in network_properties {
            props_map.insert(key, json!(prop));
        }
        result_map.insert("network_properties".to_string(), json!(props_map));
        
        Ok(json!(result_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_empty_vpns() {
        let data = b"
    SecurityControllerImpl:
    ----------------------------------------------------------------------------
    SecurityController state:
      mCurrentVpns={}
      mNetworkProperties={}

    CRITICAL dump took 0ms -- SecurityControllerImpl
        ";
        
        let parser = VpnParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["current_vpns"].is_object());
        assert!(result["network_properties"].is_object());
        
        let vpns = result["current_vpns"].as_object().unwrap();
        let props = result["network_properties"].as_object().unwrap();
        
        assert_eq!(vpns.len(), 0);
        assert_eq!(props.len(), 0);
    }

    #[test]
    fn test_parse_vpns_with_data() {
        let data = b"
    SecurityControllerImpl:
    ----------------------------------------------------------------------------
    SecurityController state:
      mCurrentVpns={0=com.example.vpn}
      mNetworkProperties={key1=value1, key2=value2}

    CRITICAL dump took 0ms -- SecurityControllerImpl
        ";
        
        let parser = VpnParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        let vpns = result["current_vpns"].as_object().unwrap();
        let props = result["network_properties"].as_object().unwrap();
        
        assert!(vpns.len() > 0);
        assert!(props.len() > 0);
    }

    #[test]
    fn test_parse_no_section() {
        let data = b"Some random data without SecurityControllerImpl section";
        
        let parser = VpnParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Should return empty result
        assert!(result["current_vpns"].is_object());
        assert!(result["network_properties"].is_object());
    }
}
