use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Debug)]
struct PowerEvent {
    timestamp: String,
    event_type: String, // SHUTDOWN, REBOOT, ON, etc.
    flags: Option<String>,
    details: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct ResetReason {
    reason: String,
    stack_trace: Vec<String>,
    timestamp: Option<String>,
    event_type: Option<String>,
    flags: Option<String>,
    details: Option<String>,
}

#[derive(Debug)]
struct PowerEntry {
    timestamp: String,  // The timestamp line like "25/11/08 17:15:29"
    reason: Option<String>,
    stack_trace: Vec<String>,
    history_events: Vec<PowerEvent>,
    other_lines: Vec<String>,
}

pub struct PowerParser;

impl Default for PowerParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Power Parser")
    }
}

impl PowerParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(PowerParser)
    }

    /// Parses a line containing pipes '|' into a PowerEvent
    fn parse_history_line(line: &str) -> Option<PowerEvent> {
        // Simple heuristic: must contain at least two pipes
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() < 3 {
            return None;
        }

        // The timestamp is usually the first part. sometimes preceded by a short time like "10:07:32 "
        let raw_ts = parts[0];
        // Clean up timestamp: take the last token if there are multiple (e.g., "10:07:32 2025-..." -> "2025-...")
        let timestamp = raw_ts.split_whitespace().last().unwrap_or(raw_ts).to_string();

        let event_type = parts[1].to_string();
        let flags = if !parts[2].is_empty() { Some(parts[2].to_string()) } else { None };
        let details = if parts.len() > 3 && !parts[3].is_empty() { Some(parts[3].to_string()) } else { None };

        Some(PowerEvent {
            timestamp,
            event_type,
            flags,
            details,
        })
    }
}

impl Parser for PowerParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        
        let mut entries: HashMap<String, PowerEntry> = HashMap::new();

        const START_DELIMITER: &str = "------ POWER OFF RESET REASON";
        
        // Find the start of the section
        if let Some(start_index) = content.find(START_DELIMITER) {
            let section_content = &content[start_index..];
            let mut lines = section_content.lines().skip(1); // Skip the header line

            let mut current_entry: Option<PowerEntry> = None;

            while let Some(line) = lines.next() {
                let trimmed = line.trim();
                if trimmed.starts_with("------") {
                    break;
                }

                // Check if this is a timestamp line (format like "25/11/08 17:15:29")
                // This marks the start of a new entry
                if trimmed.chars().next().map_or(false, |c| c.is_digit(10)) 
                    && trimmed.contains('/') && trimmed.contains(':') 
                    && !line.contains('|') {
                    // Save previous entry if exists
                    if let Some(entry) = current_entry.take() {
                        entries.insert(entry.timestamp.clone(), entry);
                    }
                    // Start new entry with this timestamp
                    current_entry = Some(PowerEntry {
                        timestamp: trimmed.to_string(),
                        reason: None,
                        stack_trace: Vec::new(),
                        history_events: Vec::new(),
                        other_lines: Vec::new(),
                    });
                    continue;
                }

                // Parse History Lines (lines with pipes)
                if line.contains('|') {
                    if let Some(event) = Self::parse_history_line(line) {
                        if let Some(ref mut entry) = current_entry {
                            entry.history_events.push(event);
                    }
                    }
                    continue;
                }

                // Parse Reason Lines
                if let Some((_, reason_text)) = trimmed.split_once("reason :") {
                    let reason_str = reason_text.trim().to_string();
                    if let Some(ref mut entry) = current_entry {
                        entry.reason = Some(reason_str);
                    }
                    continue;
                }

                // All other lines go to stack_trace if we have a reason, otherwise other_lines
                if let Some(ref mut entry) = current_entry {
                    if entry.reason.is_some() && !trimmed.is_empty() {
                        entry.stack_trace.push(trimmed.to_string());
                    } else if !trimmed.is_empty() {
                        entry.other_lines.push(trimmed.to_string());
                    }
                }
            }
            
            // Save the last entry if exists
            if let Some(entry) = current_entry {
                entries.insert(entry.timestamp.clone(), entry);
            }
        }

        // Build the result object with all entries keyed by timestamp
        let mut result_map = Map::new();
        
        for (timestamp_key, entry) in entries {
            let mut entry_obj = Map::new();
            
            // Add reason if present
            if let Some(ref reason) = entry.reason {
                entry_obj.insert("reason".to_string(), json!(reason));
            }
            
            // Add stack trace
            if !entry.stack_trace.is_empty() {
                entry_obj.insert("stack_trace".to_string(), json!(entry.stack_trace));
            }
            
            // Add history events
            if !entry.history_events.is_empty() {
                let mut events_array = Vec::new();
                for event in entry.history_events {
                    let mut event_obj = Map::new();
                    event_obj.insert("event_type".to_string(), json!(event.event_type));
                    if let Some(ref fl) = event.flags {
                        event_obj.insert("flags".to_string(), json!(fl));
                    }
                    if let Some(ref det) = event.details {
                        event_obj.insert("details".to_string(), json!(det));
                    }
                    event_obj.insert("timestamp".to_string(), json!(event.timestamp));
                    events_array.push(json!(event_obj));
                }
                entry_obj.insert("history_events".to_string(), json!(events_array));
            }
            
            // Add other lines if any
            if !entry.other_lines.is_empty() {
                entry_obj.insert("other_lines".to_string(), json!(entry.other_lines));
            }
            
            result_map.insert(timestamp_key, json!(entry_obj));
        }

        Ok(json!(result_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_power_off_reset_reason() {
        let data = b"
------ POWER OFF RESET REASON (/data/log/power_off_reset_reason.txt: 2025-03-24 13:43:33) ------
25/02/20 10:07:29
reason : no power
java.lang.Exception: It is not an exception!!
\tat com.android.server.power.ShutdownThread.shutdownInner(ShutdownThread.java:336)
\tat com.android.server.SystemServer.run(SystemServer.java:1356)
10:07:32  2025-02-20 10:07:32+0100 | SHUTDOWN | | REASON: no power [39]
2025-02-20 11:40:46+0100 |    ON    | NP    | A348BXXU7CXK1 [40]
------ END ------
        ";

        let parser = PowerParser::new().unwrap();
        let result = parser.parse(data).unwrap();

        // All entries are now keyed by the timestamp line (like "25/02/20 10:07:29")
        assert!(result.get("25/02/20 10:07:29").is_some());
        
        // Check the entry
        let entry = &result["25/02/20 10:07:29"];
        assert_eq!(entry["reason"], "no power");
        
        let stack = entry["stack_trace"].as_array().unwrap();
        assert_eq!(stack.len(), 3);
        assert!(stack[0].as_str().unwrap().contains("java.lang.Exception"));
        
        // Check history events
        let history_events = entry["history_events"].as_array().unwrap();
        assert_eq!(history_events.len(), 2);
        
        let event1 = &history_events[0];
        assert_eq!(event1["event_type"], "SHUTDOWN");
        assert_eq!(event1["details"], "REASON: no power [39]");
        assert_eq!(event1["timestamp"], "10:07:32+0100");

        let event2 = &history_events[1];
        assert_eq!(event2["event_type"], "ON");
        assert_eq!(event2["flags"], "NP");
        assert!(event2["details"].as_str().unwrap().contains("A348BXXU7CXK1"));
    }
}