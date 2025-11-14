use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;

/// A specialized parser for 'DUMP OF SERVICE package' sections.
pub struct PackageParser;

/// A helper trait to split a string at the Nth occurrence of a delimiter.
trait SplitAtNth {
    fn split_at_this_many_colons(&self, n: usize) -> Option<(&str, &str)>;
}

impl SplitAtNth for str {
    /// Splits the string at the Nth ':', returning the parts.
    fn split_at_this_many_colons(&self, n: usize) -> Option<(&str, &str)> {
        let mut indices = self.match_indices(':').skip(n - 1); // Go to the Nth (0-indexed)
        if let Some((index, _)) = indices.next() {
            Some((&self[..index], &self[index + 1..]))
        } else {
            None
        }
    }
}

impl Default for PackageParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Package Parser")
    }
}

impl PackageParser {
    /// Creates a new PackageParser.
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(PackageParser)
    }

    /// Tries to parse a line as a simple key-value pair.
    fn parse_kv_line(line: &str, map: &mut Map<String, Value>) -> bool {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "Service host process PID" => {
                    map.insert("pid".to_string(), json!(value.parse::<u32>().ok()));
                    true
                }
                "Threads in use" => {
                    map.insert("threads".to_string(), json!(value));
                    true
                }
                "Client PIDs" => {
                    let pids: Vec<u32> = value
                        .split(',')
                        .filter_map(|s| s.trim().parse::<u32>().ok())
                        .collect();
                    map.insert("client_pids".to_string(), json!(pids));
                    true
                }
                _ => false, // Not a recognized simple key-value
            }
        } else {
            false
        }
    }
    
    /// Helper to extract "value" from "key{value}" or "key: value"
    fn extract_braced_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        // Case 1: key{value}
        let key_pattern = format!("{key}{{"); 
        if let Some(start_index) = line.find(&key_pattern) {
            let value_start = start_index + key_pattern.len();
            if let Some(end_index) = line[value_start..].find('}') {
                return Some(&line[value_start .. value_start + end_index]);
            }
        }
        
        // Case 2: key: value
        let key_pattern_colon = format!("{key}:");
        if let Some(start_index) = line.find(&key_pattern_colon) {
            let value_start = start_index + key_pattern_colon.len();
            let value = &line[value_start..].trim();
            // Take up to the next comma or end of string
            return Some(value.split(',').next().unwrap_or(value).trim());
        }
        
        None
    }

    /// Tries to parse a log entry, which may span multiple lines.
    /// It takes the current line and a peekable iterator for subsequent lines.
    fn parse_log_entry<'a, I>(
        current_line: &str,
        lines_iter: &mut std::iter::Peekable<I>,
    ) -> Option<Value>
    where
        I: Iterator<Item = &'a str>,
    {
        // Check for timestamp format "YYYY-MM-DD HH:MM:SS.mmm:"
        if current_line.len() < 24 || current_line.chars().nth(4) != Some('-') || current_line.chars().nth(23) != Some(':') {
            return None;
        }
        
        if let Some((timestamp, message)) = current_line.split_at_this_many_colons(3) {
            let timestamp = timestamp.trim();
            let message = message.trim_start();
            
            let mut log_map = Map::new();
            log_map.insert("timestamp".to_string(), json!(timestamp));

            // Case 1: START INSTALL PACKAGE (multi-line)
            if message.starts_with("START INSTALL PACKAGE:") {
                log_map.insert("event_type".to_string(), json!("START_INSTALL"));
                
                if let Some(observer) = Self::extract_braced_value(message, "observer") {
                    log_map.insert("observer".to_string(), json!(observer));
                }
                
                // Consume next lines
                while let Some(next_line) = lines_iter.peek() {
                    let next_line_trimmed = next_line.trim();
                    if next_line_trimmed.starts_with("stagedDir") {
                        log_map.insert("stagedDir".to_string(), json!(Self::extract_braced_value(next_line_trimmed, "stagedDir")));
                    } else if next_line_trimmed.starts_with("pkg") {
                        log_map.insert("pkg".to_string(), json!(Self::extract_braced_value(next_line_trimmed, "pkg")));
                    } else if next_line_trimmed.starts_with("versionCode") {
                        let vc = Self::extract_braced_value(next_line_trimmed, "versionCode")
                                   .and_then(|s| s.parse::<u64>().ok());
                        log_map.insert("versionCode".to_string(), json!(vc));
                    } else if next_line_trimmed.starts_with("Request from") {
                         log_map.insert("request_from".to_string(), json!(Self::extract_braced_value(next_line_trimmed, "Request from")));
                    } else {
                        break; // Not part of this block
                    }
                    lines_iter.next(); // Consume the line
                }
                return Some(json!(log_map));
            }

            // Case 2: result of install (single-line)
            if message.starts_with("result of install:") {
                log_map.insert("event_type".to_string(), json!("INSTALL_RESULT"));
                log_map.insert("message".to_string(), json!(message));
                return Some(json!(log_map));
            }

            // Case 3: setApplicationCategoryHint (single-line, with commas)
            if message.starts_with("setApplicationCategoryHint,") {
                log_map.insert("event_type".to_string(), json!("SET_CATEGORY_HINT"));
                // "setApplicationCategoryHint, pkg: com.google..., caller: com.android.vending/10253"
                let parts: Vec<&str> = message.split(',').map(|s| s.trim()).collect();
                for part in parts.iter().skip(1) { // Skip "setApplicationCategoryHint"
                    if let Some((key, value)) = part.split_once(':') {
                        log_map.insert(key.trim().to_string(), json!(value.trim()));
                    }
                }
                return Some(json!(log_map));
            }
        }

        None
    }
}

impl Parser for PackageParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut results = Vec::new();

        const START_DELIMITER: &str = 
            "\n-------------------------------------------------------------------------------\n\
             DUMP OF SERVICE package:\n";
        
        const END_DELIMITER: &str = 
            "\n-------------------------------------------------------------------------------\n";

        for block in content.split(START_DELIMITER).skip(1) {
            let mut section_map = Map::new();
            let mut install_logs = Vec::new();

            let lines = block
                .lines()
                .take_while(|&line| !line.starts_with(END_DELIMITER.trim()));
            
            let mut lines_iter = lines.peekable(); // Use a peekable iterator

            while let Some(line) = lines_iter.next() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if PackageParser::parse_kv_line(line, &mut section_map) {
                    // Handled by parse_kv_line
                } else if let Some(log_entry) = PackageParser::parse_log_entry(line, &mut lines_iter) {
                    // parse_log_entry returns a parsed Value and consumes from the iterator
                    install_logs.push(log_entry);
                }
                // Unparsed lines (like "Some other random line") are now skipped
            }
            
            if !install_logs.is_empty() {
                section_map.insert("install_logs".to_string(), json!(install_logs));
            }
            
            if !section_map.is_empty() {
                results.push(json!(section_map));
            }
        }
        
        Ok(json!(results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;
    use serde_json::json;

    #[test]
    fn test_parse_package_service_block() {
        let data = b"
Junk before
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Service host process PID: 1486
Threads in use: 0/32
Client PIDs: 25036, 24988
Some other random line
2025-03-28 02:22:45.340: START INSTALL PACKAGE: observer{133061357}
          stagedDir{/data/app/vmdl1456751445.tmp}
          pkg{com.google.android.apps.youtube.music}
          versionCode{81253240}
          Request from{com.android.vending}
2025-03-28 02:22:45.717: result of install: 1{133061357}
2025-03-28 02:22:46.062: setApplicationCategoryHint, pkg: com.google.android.apps.youtube.music, oldCategory: 1, newCategory: 1, manifestCategory: 1, caller: com.android.vending/10253
-------------------------------------------------------------------------------
DUMP OF SERVICE other:
Some other data
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Updated expected JSON: "other_info" is no longer present.
        let expected = json!([
            {
                "pid": 1486,
                "threads": "0/32",
                "client_pids": [25036, 24988],
                "install_logs": [
                    {
                        "timestamp": "2025-03-28 02:22:45.340",
                        "event_type": "START_INSTALL",
                        "observer": "133061357",
                        "stagedDir": "/data/app/vmdl1456751445.tmp",
                        "pkg": "com.google.android.apps.youtube.music",
                        "versionCode": 81253240,
                        "request_from": "com.android.vending"
                    },
                    {
                        "timestamp": "2025-03-28 02:22:45.717",
                        "event_type": "INSTALL_RESULT",
                        "message": "result of install: 1{133061357}"
                    },
                    {
                        "timestamp": "2025-03-28 02:22:46.062",
                        "event_type": "SET_CATEGORY_HINT",
                        "pkg": "com.google.android.apps.youtube.music",
                        "oldCategory": "1",
                        "newCategory": "1",
                        "manifestCategory": "1",
                        "caller": "com.android.vending/10253"
                    }
                ]
            }
        ]);
        assert_eq!(result, expected);
    }
}