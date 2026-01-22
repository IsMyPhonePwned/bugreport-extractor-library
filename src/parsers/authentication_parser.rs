use super::Parser;
use serde_json::{json, Value};
use std::error::Error;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use regex::Regex;

/// Represents a single authentication event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationEvent {
    pub timestamp: String,  // Full timestamp: "MM-DD HH:MM:SS.mmm"
    pub user_id: Option<u32>,
    pub success: bool,
    pub auth_type: Option<String>,  // biometric, passcode, password, pattern, etc.
    pub raw_message: String,  // Original log message for reference
}

/// A parser for user authentication events in Android bug reports.
/// Extracts authentication attempts from keystore and other security logs.
pub struct AuthenticationParser;

impl Default for AuthenticationParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Authentication Parser")
    }
}

impl AuthenticationParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(AuthenticationParser)
    }

    /// Parse a logcat timestamp from format "MM-DD HH:MM:SS.mmm"
    /// Returns (timestamp_string, remaining_line)
    fn parse_logcat_timestamp(line: &str) -> Option<(String, &str)> {
        // Logcat format: "MM-DD HH:MM:SS.mmm  PID  TID  PID LEVEL TAG : content"
        // Example: "12-18 10:31:13.784  1017   684 16027 I keystore2: ..."
        
        let trimmed = line.trim();
        
        // Check if line starts with timestamp pattern: "MM-DD HH:MM:SS.mmm"
        if trimmed.len() < 18 {
            return None;
        }
        
        let bytes = trimmed.as_bytes();
        // Check pattern: MM-DD HH:MM:SS.mmm (18 characters)
        if bytes.len() >= 18 &&
           bytes[2] == b'-' &&
           bytes[5] == b' ' &&
           bytes[8] == b':' &&
           bytes[11] == b':' &&
           bytes[14] == b'.' {
            // Extract timestamp (first 18 characters)
            let timestamp = trimmed[..18].to_string();
            // Return remaining line after timestamp and whitespace
            let remaining = trimmed[18..].trim_start();
            return Some((timestamp, remaining));
        }
        
        None
    }

    /// Extract user ID from a message
    /// Looks for patterns like "user 0", "user 10", etc.
    fn extract_user_id(message: &str) -> Option<u32> {
        let lower = message.to_lowercase();
        
        // Look for "user X" pattern
        if let Some(user_pos) = lower.find("user ") {
            let after_user = &lower[user_pos + 5..];
            // Find the number after "user "
            let num_str: String = after_user
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            
            if !num_str.is_empty() {
                return num_str.parse::<u32>().ok();
            }
        }
        
        None
    }

    /// Extract authentication type from message
    /// Looks for: biometric, passcode, password, pattern, pin, etc.
    fn extract_auth_type(message: &str) -> Option<String> {
        let lower = message.to_lowercase();
        
        // Common authentication types
        let auth_types = vec![
            "biometric",
            "passcode",
            "password",
            "pattern",
            "pin",
            "fingerprint",
            "face",
            "iris",
            "voice",
        ];
        
        for auth_type in auth_types {
            if lower.contains(auth_type) {
                return Some(auth_type.to_string());
            }
        }
        
        None
    }

    /// Determine if authentication was successful
    /// Looks for success/failure keywords
    fn is_success(message: &str) -> bool {
        let lower = message.to_lowercase();
        
        // Success indicators
        let success_keywords = vec![
            "successfully",
            "success",
            "unlocked",
            "authenticated",
            "verified",
        ];
        
        // Failure indicators
        let failure_keywords = vec![
            "failed",
            "failure",
            "denied",
            "rejected",
            "error",
            "invalid",
        ];
        
        // Check for failure first (more specific)
        for keyword in failure_keywords {
            if lower.contains(keyword) {
                return false;
            }
        }
        
        // Check for success
        for keyword in success_keywords {
            if lower.contains(keyword) {
                return true;
            }
        }
        
        // Default to false if no clear indicator
        false
    }

    /// Strip file path and line number from message
    /// Removes patterns like "system/security/keystore2/src/super_key.rs:1046 -"
    /// Uses a simple regex pattern to match keystore2 file paths with line numbers
    fn strip_file_path(message: &str) -> String {
        // Specific regex: match keystore2 paths ending with :digits followed by optional space/dash/colon
        // Pattern: system/security/keystore2...:[digits] followed by optional whitespace/dash/colon
        let re = Regex::new(r"system/security/keystore2[^\s]+:\d+\s*[-:]?\s*").unwrap();
        re.replace(message, "").trim().to_string()
    }

    /// Parse a single authentication log line
    fn parse_auth_line(line: &str) -> Option<AuthenticationEvent> {
        // Parse timestamp
        let (timestamp, remaining) = Self::parse_logcat_timestamp(line)?;
        
        // Find the content after TAG (look for ": " pattern)
        // Format: "PID  TID  PID LEVEL TAG : content"
        let content = if let Some(tag_pos) = remaining.find(": ") {
            &remaining[tag_pos + 2..]
        } else {
            remaining
        };
        
        // Strip file paths and line numbers
        let clean_message = Self::strip_file_path(content);
        
        // We already filtered for "Successfully unlocked user" before calling this function
        // So we can skip the redundant check here
        
        // Extract information
        let user_id = Self::extract_user_id(&clean_message);
        let success = Self::is_success(&clean_message);
        let auth_type = Self::extract_auth_type(&clean_message);
        
        Some(AuthenticationEvent {
            timestamp,
            user_id,
            success,
            auth_type,
            raw_message: clean_message,
        })
    }
}

impl Parser for AuthenticationParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut events = Vec::new();
        
        // Parse both "SYSTEM LOG" and "SYSTEM LOG AFTER DONE" sections
        let sections = vec![
            ("------ SYSTEM LOG (logcat", " was the duration of 'SYSTEM LOG' ------"),
            ("------ SYSTEM LOG AFTER DONE", " was the duration of 'SYSTEM LOG AFTER DONE' ------"),
        ];
        
        for (start_delimiter, end_suffix) in sections {
            if let Some(start_index) = content.find(start_delimiter) {
                // Find the end of the section
                let section_start = start_index + start_delimiter.len();
                let remaining_content = &content[section_start..];
                
                // Look for the end delimiter pattern
                let end_index = remaining_content
                    .find("------ ")
                    .and_then(|prefix_pos| {
                        let after_prefix = &remaining_content[prefix_pos..];
                        if after_prefix.contains(end_suffix) {
                            // Find the actual end position
                            after_prefix.find(end_suffix).map(|suffix_pos| {
                                section_start + prefix_pos + suffix_pos + end_suffix.len()
                            })
                        } else {
                            None
                        }
                    })
                    .unwrap_or(content.len());
                
                // Only parse lines within this section
                // Use byte-level search for better performance
                let section_content = &content[section_start..end_index];
                
                // Fast pre-filter: only process lines that contain "Successfully unlocked user"
                // This avoids expensive parsing for most lines (most lines won't match)
                const SEARCH_PATTERN: &[u8] = b"Successfully unlocked user";
                
                for line in section_content.lines() {
                    // Quick byte-level check before any string operations
                    // This is much faster than converting to lowercase and using contains()
                    let line_bytes = line.as_bytes();
                    if !line_bytes.windows(SEARCH_PATTERN.len()).any(|window| {
                        window.eq_ignore_ascii_case(SEARCH_PATTERN)
                    }) {
                        continue; // Skip this line early - avoids all parsing overhead
                    }
                    
                    // Only parse if the line contains our pattern
                    if let Some(event) = Self::parse_auth_line(line) {
                        events.push(event);
                    }
                }
            }
        }
        
        let mut result = HashMap::new();
        result.insert("events".to_string(), json!(events));
        result.insert("total_events".to_string(), json!(events.len()));
        
        Ok(json!(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_keystore_unlock_success() {
        let data = b"------ SYSTEM LOG AFTER DONE (logcat -v threadtime -v printable -v uid -d *:v -T 2026-01-21 11:07:03.000) ------\n12-18 10:31:13.784  1017   684 16027 I keystore2: system/security/keystore2/src/super_key.rs:1046 - Successfully unlocked user 0 with biometric 3704621293814964787\n------ 0.302s was the duration of 'SYSTEM LOG AFTER DONE' ------";
        
        let parser = AuthenticationParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["events"].is_array());
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        
        let event = &events[0];
        assert_eq!(event["timestamp"], "12-18 10:31:13.784");
        assert_eq!(event["user_id"], 0);
        assert_eq!(event["success"], true);
        assert_eq!(event["auth_type"], "biometric");
        assert!(event["raw_message"].as_str().unwrap().contains("Successfully unlocked user 0 with biometric"));
        // Verify file path and line number are stripped
        assert!(!event["raw_message"].as_str().unwrap().contains("super_key.rs:1046"));
    }

    #[test]
    fn test_parse_multiple_events() {
        let data = b"------ SYSTEM LOG AFTER DONE (logcat -v threadtime -v printable -v uid -d *:v -T 2026-01-21 11:07:03.000) ------\n12-18 10:31:13.784  1017   684 16027 I keystore2: system/security/keystore2/src/super_key.rs:1046 - Successfully unlocked user 0 with biometric 3704621293814964787\n12-18 10:32:15.123  1017   684 16027 I keystore2: system/security/keystore2/src/super_key.rs:1046 - Successfully unlocked user 10 with passcode\n12-18 10:33:20.456  1017   684 16027 I keystore2: system/security/keystore2/src/super_key.rs:1046 - Successfully unlocked user 5 with password\n------ 0.302s was the duration of 'SYSTEM LOG AFTER DONE' ------";
        
        let parser = AuthenticationParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert_eq!(result["total_events"], 3);
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        
        // Check first event
        assert_eq!(events[0]["user_id"], 0);
        assert_eq!(events[0]["success"], true);
        assert_eq!(events[0]["auth_type"], "biometric");
        
        // Check second event
        assert_eq!(events[1]["user_id"], 10);
        assert_eq!(events[1]["success"], true);
        assert_eq!(events[1]["auth_type"], "passcode");
        
        // Check third event
        assert_eq!(events[2]["user_id"], 5);
        assert_eq!(events[2]["success"], true);
        assert_eq!(events[2]["auth_type"], "password");
    }

    #[test]
    fn test_parse_different_auth_types() {
        let data = b"------ SYSTEM LOG AFTER DONE (logcat -v threadtime -v printable -v uid -d *:v -T 2026-01-21 11:07:03.000) ------\n12-18 10:31:13.784  1017   684 16027 I keystore2: Successfully unlocked user 0 with fingerprint\n12-18 10:31:14.123  1017   684 16027 I keystore2: Successfully unlocked user 1 with face\n12-18 10:31:15.456  1017   684 16027 I keystore2: Successfully unlocked user 2 with pattern\n12-18 10:31:16.789  1017   684 16027 I keystore2: Successfully unlocked user 3 with pin\n------ 0.302s was the duration of 'SYSTEM LOG AFTER DONE' ------";
        
        let parser = AuthenticationParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0]["auth_type"], "fingerprint");
        assert_eq!(events[1]["auth_type"], "face");
        assert_eq!(events[2]["auth_type"], "pattern");
        assert_eq!(events[3]["auth_type"], "pin");
    }

    #[test]
    fn test_strip_file_path() {
        let message = "system/security/keystore2/src/super_key.rs:1046 - Successfully unlocked user 0";
        let cleaned = AuthenticationParser::strip_file_path(message);
        assert!(!cleaned.contains("super_key.rs"));
        assert!(!cleaned.contains("1046"));
        assert!(cleaned.contains("Successfully unlocked user 0"));
    }

    #[test]
    fn test_extract_user_id() {
        assert_eq!(AuthenticationParser::extract_user_id("Successfully unlocked user 0 with biometric"), Some(0));
        assert_eq!(AuthenticationParser::extract_user_id("Failed to authenticate user 10 with passcode"), Some(10));
        assert_eq!(AuthenticationParser::extract_user_id("No user mentioned"), None);
    }

    #[test]
    fn test_extract_auth_type() {
        assert_eq!(AuthenticationParser::extract_auth_type("unlocked with biometric"), Some("biometric".to_string()));
        assert_eq!(AuthenticationParser::extract_auth_type("authenticated with passcode"), Some("passcode".to_string()));
        assert_eq!(AuthenticationParser::extract_auth_type("verified with password"), Some("password".to_string()));
        assert_eq!(AuthenticationParser::extract_auth_type("no auth type"), None);
    }

    #[test]
    fn test_is_success() {
        assert_eq!(AuthenticationParser::is_success("Successfully unlocked user 0"), true);
        assert_eq!(AuthenticationParser::is_success("Failed to authenticate"), false);
        assert_eq!(AuthenticationParser::is_success("Authentication denied"), false);
        assert_eq!(AuthenticationParser::is_success("User verified"), true);
    }

    #[test]
    fn test_parse_empty_data() {
        let data = b"Some random log line without authentication";
        
        let parser = AuthenticationParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert_eq!(result["total_events"], 0);
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_parse_only_in_section() {
        // Test that events outside the section are not parsed
        let data = b"12-18 10:31:13.784  1017   684 16027 I keystore2: Successfully unlocked user 0 with biometric\n------ SYSTEM LOG AFTER DONE (logcat -v threadtime -v printable -v uid -d *:v -T 2026-01-21 11:07:03.000) ------\n12-18 10:32:15.123  1017   684 16027 I keystore2: Successfully unlocked user 1 with passcode\n------ 0.302s was the duration of 'SYSTEM LOG AFTER DONE' ------\n12-18 10:33:20.456  1017   684 16027 I keystore2: Successfully unlocked user 2 with password";
        
        let parser = AuthenticationParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Should only find 1 event (the one inside the section)
        assert_eq!(result["total_events"], 1);
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["user_id"], 1);
        assert_eq!(events[0]["auth_type"], "passcode");
    }

    #[test]
    fn test_parse_logcat_timestamp() {
        let line = "12-18 10:31:13.784  1017   684 16027 I keystore2: content";
        let (timestamp, remaining) = AuthenticationParser::parse_logcat_timestamp(line).unwrap();
        
        assert_eq!(timestamp, "12-18 10:31:13.784");
        assert!(remaining.contains("keystore2"));
    }
}
