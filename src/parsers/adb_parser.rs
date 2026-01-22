use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;

/// A parser for ADB (Android Debug Bridge) sections in Android bug reports.
/// Extracts connection information, authorized keys, and PC connection details.
pub struct AdbParser;

impl Default for AdbParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the ADB Parser")
    }
}

impl AdbParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(AdbParser)
    }

    /// Parse a key=value line, handling various value types
    fn parse_key_value(line: &str) -> Option<(String, Value)> {
        let trimmed = line.trim();
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value_str = trimmed[eq_pos+1..].trim();
            
            // Try to parse as different types
            if value_str == "true" {
                return Some((key, json!(true)));
            } else if value_str == "false" {
                return Some((key, json!(false)));
            } else {
                // String value
                return Some((key, json!(value_str)));
            }
        }
        None
    }

    /// Parse the ADB MANAGER STATE section
    /// Format is nested JSON-like structure with braces
    fn parse_adb_manager_state(lines: &[&str], start_idx: usize) -> (Map<String, Value>, usize) {
        let mut state_map = Map::new();
        let mut idx = start_idx;
        let mut brace_level = 0;
        let mut in_debugging_manager = false;
        let mut debugging_manager = Map::new();
        
        while idx < lines.len() {
            let line = lines[idx].trim();
            
            if line.is_empty() {
                idx += 1;
                continue;
            }
            
            // Track brace levels
            brace_level += line.matches('{').count() as i32;
            brace_level -= line.matches('}').count() as i32;
            
            // Check if we're entering/exiting debugging_manager
            if line.contains("debugging_manager={") {
                in_debugging_manager = true;
                idx += 1;
                continue;
            }
            
            if in_debugging_manager {
                // Check if we're exiting debugging_manager
                if line == "}" && brace_level <= 1 {
                    state_map.insert("debugging_manager".to_string(), json!(debugging_manager));
                    in_debugging_manager = false;
                    idx += 1;
                    continue;
                }
                
                // Parse key=value pairs within debugging_manager
                if let Some((key, value)) = Self::parse_key_value(line) {
                    debugging_manager.insert(key, value);
                }
            } else {
                // Parse top-level key=value pairs
                if let Some((key, value)) = Self::parse_key_value(line) {
                    state_map.insert(key, value);
                }
            }
            
            // Stop if we've closed all braces
            if brace_level <= 0 && line.contains('}') {
                idx += 1;
                break;
            }
            
            idx += 1;
        }
        
        (state_map, idx)
    }

    /// Extract user keys from the user_keys field
    /// Format: RSA public key + identifier (e.g., "MIIBCgKCAQEA... rust-webadb")
    fn parse_user_keys(user_keys_str: &str) -> Vec<Map<String, Value>> {
        let mut keys = Vec::new();
        
        // Split by potential key boundaries (look for base64-like patterns followed by identifiers)
        // User keys are typically RSA public keys in base64 format followed by an identifier
        let parts: Vec<&str> = user_keys_str.split_whitespace().collect();
        
        let mut current_key = String::new();
        let mut current_identifier = None;
        
        for part in parts {
            // Check if this part looks like a base64 key (starts with MII or similar)
            if part.starts_with("MII") || part.len() > 100 {
                // This is likely a key
                if !current_key.is_empty() && current_identifier.is_some() {
                    // Save previous key
                    let mut key_map = Map::new();
                    key_map.insert("key".to_string(), json!(current_key.trim()));
                    key_map.insert("identifier".to_string(), json!(current_identifier.unwrap()));
                    keys.push(key_map);
                }
                current_key = part.to_string();
                current_identifier = None;
            } else if !current_key.is_empty() {
                // This is likely an identifier
                current_identifier = Some(part.to_string());
            }
        }
        
        // Add the last key if we have one
        if !current_key.is_empty() {
            let mut key_map = Map::new();
            key_map.insert("key".to_string(), json!(current_key.trim()));
            if let Some(identifier) = current_identifier {
                key_map.insert("identifier".to_string(), json!(identifier));
            }
            keys.push(key_map);
        }
        
        // If we couldn't parse it properly, just return the whole string as one entry
        if keys.is_empty() && !user_keys_str.trim().is_empty() {
            let mut key_map = Map::new();
            key_map.insert("raw".to_string(), json!(user_keys_str.trim()));
            keys.push(key_map);
        }
        
        keys
    }

    /// Extract information from keystore data
    /// The keystore contains binary data, but we can extract text parts
    fn parse_keystore(keystore_str: &str) -> Map<String, Value> {
        let mut keystore_map = Map::new();
        
        // Try to extract readable parts
        // Look for patterns like "adbKey/", "version", "lastConnection"
        if keystore_str.contains("adbKey/") {
            keystore_map.insert("has_adb_key".to_string(), json!(true));
        }
        
        if keystore_str.contains("version") {
            keystore_map.insert("has_version".to_string(), json!(true));
        }
        
        if keystore_str.contains("lastConnection") {
            keystore_map.insert("has_last_connection".to_string(), json!(true));
        }
        
        // Try to extract the key identifier if present (e.g., "rust-webadb")
        if let Some(key_start) = keystore_str.find("MII") {
            // Try to find identifier after the key
            let after_key = &keystore_str[key_start..];
            if let Some(id_start) = after_key.find("rust-") {
                let id_part = &after_key[id_start..];
                if let Some(id_end) = id_part.find(char::is_control) {
                    let identifier = &id_part[..id_end].trim();
                    if !identifier.is_empty() {
                        keystore_map.insert("key_identifier".to_string(), json!(identifier));
                    }
                }
            }
        }
        
        keystore_map.insert("raw_length".to_string(), json!(keystore_str.len()));
        
        keystore_map
    }
}

impl Parser for AdbParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut result_map = Map::new();

        const START_DELIMITER: &str = "DUMP OF SERVICE adb:";
        const END_DELIMITER_PREFIX: &str = "---------"; // Generic end for dumpsys sections

        if let Some(start_index) = content.find(START_DELIMITER) {
            let end_index = content[start_index..]
                .find(END_DELIMITER_PREFIX)
                .map_or(content.len(), |i| start_index + i);
            
            let adb_section = &content[start_index..end_index];
            let lines: Vec<&str> = adb_section.lines().collect();
            
            let mut idx = 0;
            
            // Parse service information
            while idx < lines.len() {
                let line = lines[idx].trim();
                
                if line.is_empty() {
                    idx += 1;
                    continue;
                }
                
                // Parse service host process PID
                if line.starts_with("Service host process PID:") {
                    if let Some(pid_str) = line.split(':').nth(1) {
                        if let Ok(pid) = pid_str.trim().parse::<u32>() {
                            result_map.insert("service_pid".to_string(), json!(pid));
                        }
                    }
                }
                
                // Parse threads in use
                if line.starts_with("Threads in use:") {
                    if let Some(threads_str) = line.split(':').nth(1) {
                        result_map.insert("threads_in_use".to_string(), json!(threads_str.trim()));
                    }
                }
                
                // Parse client PIDs
                if line.starts_with("Client PIDs:") {
                    if let Some(pids_str) = line.split(':').nth(1) {
                        let pids: Vec<u32> = pids_str
                            .split(',')
                            .filter_map(|s| s.trim().parse::<u32>().ok())
                            .collect();
                        result_map.insert("client_pids".to_string(), json!(pids));
                    }
                }
                
                // Parse ADB MANAGER STATE
                if line.starts_with("ADB MANAGER STATE") || line == "{" {
                    let (state_map, new_idx) = Self::parse_adb_manager_state(&lines, idx);
                    
                    // Process debugging_manager if present
                    if let Some(debugging_manager) = state_map.get("debugging_manager") {
                        if let Some(dm_obj) = debugging_manager.as_object() {
                            let mut processed_dm = Map::new();
                            
                            // Copy all fields
                            for (key, value) in dm_obj {
                                processed_dm.insert(key.clone(), value.clone());
                            }
                            
                            // Process user_keys if present
                            if let Some(user_keys_value) = dm_obj.get("user_keys") {
                                if let Some(user_keys_str) = user_keys_value.as_str() {
                                    let parsed_keys = Self::parse_user_keys(user_keys_str);
                                    processed_dm.insert("user_keys_parsed".to_string(), json!(parsed_keys));
                                }
                            }
                            
                            // Process keystore if present
                            if let Some(keystore_value) = dm_obj.get("keystore") {
                                if let Some(keystore_str) = keystore_value.as_str() {
                                    let parsed_keystore = Self::parse_keystore(keystore_str);
                                    processed_dm.insert("keystore_parsed".to_string(), json!(parsed_keystore));
                                }
                            }
                            
                            result_map.insert("debugging_manager".to_string(), json!(processed_dm));
                        }
                    }
                    
                    // Add other state fields
                    for (key, value) in state_map {
                        if key != "debugging_manager" {
                            result_map.insert(key, value);
                        }
                    }
                    
                    idx = new_idx;
                    continue;
                }
                
                idx += 1;
            }
            
            Ok(json!(result_map))
        } else {
            Ok(json!({}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_adb_basic() {
        let data = b"
DUMP OF SERVICE adb:
Service host process PID: 1391
Threads in use: 2/32
Client PIDs: 2059, 27958, 638
ADB MANAGER STATE (dumpsys adb):
{
  debugging_manager={
    connected_to_adb=true
    last_key_received=AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00
    user_keys=MIIBCgKCAQEA...ANONYMIZED_KEY...IDAQAB rust-webadb
  }
}
--------- 0.213s was the duration of dumpsys adb, ending at: 2026-01-21 11:08:39
        ";
        
        let parser = AdbParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Check service information
        assert_eq!(result["service_pid"], 1391);
        assert_eq!(result["threads_in_use"], "2/32");
        assert!(result["client_pids"].is_array());
        let client_pids = result["client_pids"].as_array().unwrap();
        assert_eq!(client_pids.len(), 3);
        assert_eq!(client_pids[0], 2059);
        
        // Check debugging_manager
        assert!(result["debugging_manager"].is_object());
        let dm = result["debugging_manager"].as_object().unwrap();
        assert_eq!(dm["connected_to_adb"], true);
        assert_eq!(dm["last_key_received"], "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00");
        
        // Check user_keys_parsed
        assert!(dm["user_keys_parsed"].is_array());
        let user_keys = dm["user_keys_parsed"].as_array().unwrap();
        assert!(user_keys.len() >= 1);
        let first_key = user_keys[0].as_object().unwrap();
        assert!(first_key.contains_key("key"));
        assert_eq!(first_key["identifier"], "rust-webadb");
    }

    #[test]
    fn test_parse_adb_not_connected() {
        let data = b"
DUMP OF SERVICE adb:
Service host process PID: 1391
ADB MANAGER STATE (dumpsys adb):
{
  debugging_manager={
    connected_to_adb=false
  }
}
--------- 0.213s was the duration of dumpsys adb, ending at: 2026-01-21 11:08:39
        ";
        
        let parser = AdbParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["debugging_manager"].is_object());
        let dm = result["debugging_manager"].as_object().unwrap();
        assert_eq!(dm["connected_to_adb"], false);
    }

    #[test]
    fn test_parse_user_keys() {
        let user_keys_str = "MIIBCgKCAQEA...ANONYMIZED_KEY...IDAQAB rust-webadb";
        
        let keys = AdbParser::parse_user_keys(user_keys_str);
        assert!(keys.len() >= 1);
        let first_key = &keys[0];
        assert!(first_key.contains_key("key"));
        assert_eq!(first_key["identifier"], "rust-webadb");
    }

    #[test]
    fn test_parse_keystore() {
        let keystore_str = "ABX 2 keyStoreo version 2 adbKey/ key tMIIBCgKCAQEA...ANONYMIZED_KEY... rust-webadb lastConnection 33";
        
        let keystore = AdbParser::parse_keystore(keystore_str);
        assert_eq!(keystore["has_adb_key"], true);
        assert_eq!(keystore["has_version"], true);
        assert_eq!(keystore["has_last_connection"], true);
    }

    #[test]
    fn test_parse_empty_section() {
        let data = b"
Some other content here
Not ADB related
        ";
        
        let parser = AdbParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Should return empty JSON object when section not found
        assert!(result.is_object());
        assert!(result.as_object().unwrap().is_empty());
    }
}
