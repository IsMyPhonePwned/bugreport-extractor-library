use super::Parser;
use serde_json::{json, Value};
use std::error::Error;
use serde::Serialize;

#[derive(Serialize, Debug)]
struct PowerEvent {
    timestamp: String,
    event_type: String, // SHUTDOWN, REBOOT, ON, etc.
    flags: Option<String>,
    details: Option<String>,
}

#[derive(Serialize, Debug)]
struct ResetReason {
    reason: String,
    stack_trace: Vec<String>,
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
        
        let mut history = Vec::new();
        let mut reasons = Vec::new();

        const START_DELIMITER: &str = "------ POWER OFF RESET REASON";
        
        // Find the start of the section
        if let Some(start_index) = content.find(START_DELIMITER) {
            let section_content = &content[start_index..];
            let mut lines = section_content.lines().skip(1); // Skip the header line

            let mut current_reason: Option<ResetReason> = None;

            while let Some(line) = lines.next() {
                let trimmed = line.trim();
                if trimmed.starts_with("------") {
                    break;
                }

                // Parse History Lines 
                if line.contains('|') {
                    if let Some(event) = Self::parse_history_line(line) {
                        history.push(event);
                    }
                    // Reset current reason parsing if we hit a history line
                    if let Some(reason) = current_reason.take() {
                        reasons.push(reason);
                    }
                    continue;
                }

                // Parse Reason Lines
                if let Some((_, reason_text)) = trimmed.split_once("reason :") {
                    // Save previous reason if exists
                    if let Some(reason) = current_reason.take() {
                        reasons.push(reason);
                    }
                    current_reason = Some(ResetReason {
                        reason: reason_text.trim().to_string(),
                        stack_trace: Vec::new(),
                    });
                    continue;
                }

                // If we are currently parsing a reason, add lines to stack trace
                if let Some(ref mut reason_obj) = current_reason {
                    // Stop capturing stack trace if we hit an empty line or a date-like line
                    if trimmed.is_empty() {
                       // continue capturing? often stack traces have no empty lines inside.
                       // let's assume empty line ends the block for safety, or we can just keep adding.
                    } else if trimmed.chars().next().map_or(false, |c| c.is_digit(10)) {
                        // Likely a timestamp line "25/02/20 10:07:29", stop capturing
                        reasons.push(current_reason.take().unwrap());
                    } else {
                        reason_obj.stack_trace.push(trimmed.to_string());
                    }
                }
            }
            // Push the last one if exists
            if let Some(reason) = current_reason {
                reasons.push(reason);
            }
        }

        Ok(json!({
            "power_history": history,
            "reset_reasons": reasons
        }))
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

        let history = result["power_history"].as_array().unwrap();
        assert_eq!(history.len(), 2);
        
        let event1 = &history[0];
        assert_eq!(event1["timestamp"], "10:07:32+0100"); 
        
        assert_eq!(event1["event_type"], "SHUTDOWN");
        assert_eq!(event1["details"], "REASON: no power [39]");

        let event2 = &history[1];
        assert_eq!(event2["event_type"], "ON");
        assert_eq!(event2["flags"], "NP");
        assert!(event2["details"].as_str().unwrap().contains("A348BXXU7CXK1"));

        let reasons = result["reset_reasons"].as_array().unwrap();
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0]["reason"], "no power");
        
        let stack = reasons[0]["stack_trace"].as_array().unwrap();
        assert_eq!(stack.len(), 3);
        assert!(stack[0].as_str().unwrap().contains("java.lang.Exception"));
    }
}