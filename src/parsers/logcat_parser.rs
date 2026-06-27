use super::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;

const MAX_EVENTS: usize = 100_000;

/// One logcat line from SYSTEM LOG / SYSTEM LOG AFTER DONE sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogcatEvent {
    pub timestamp: String,
    pub uid: u32,
    pub pid: u32,
    pub tid: u32,
    pub level: String,
    pub tag: String,
    pub message: String,
    pub section: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
}

/// Parses Android bugreport logcat buffers (SYSTEM LOG sections).
pub struct LogcatParser;

impl Default for LogcatParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Logcat Parser")
    }
}

impl LogcatParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(LogcatParser)
    }

    /// `MM-DD HH:MM:SS.mmm` → `(timestamp, rest)`
    pub fn parse_logcat_timestamp(line: &str) -> Option<(String, &str)> {
        let trimmed = line.trim();
        if trimmed.len() < 18 {
            return None;
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 18
            && bytes[2] == b'-'
            && bytes[5] == b' '
            && bytes[8] == b':'
            && bytes[11] == b':'
            && bytes[14] == b'.'
        {
            let timestamp = trimmed[..18].to_string();
            let remaining = trimmed[18..].trim_start();
            return Some((timestamp, remaining));
        }
        None
    }

    /// Parse threadtime body: `UID PID TID LEVEL TAG: message`
    fn parse_logcat_body(remaining: &str) -> Option<(u32, u32, u32, String, String, String)> {
        let mut parts = remaining.split_whitespace();
        let uid: u32 = parts.next()?.parse().ok()?;
        let pid: u32 = parts.next()?.parse().ok()?;
        let tid: u32 = parts.next()?.parse().ok()?;
        let level = parts.next()?.to_string();
        let rest: String = parts.collect::<Vec<_>>().join(" ");
        if rest.is_empty() {
            return None;
        }
        let (tag, message) = if let Some((t, m)) = rest.split_once(':') {
            (t.trim().to_string(), m.trim().to_string())
        } else {
            (String::new(), rest)
        };
        Some((uid, pid, tid, level, tag, message))
    }

    fn parse_line(line: &str, section: &str) -> Option<LogcatEvent> {
        let (timestamp, remaining) = Self::parse_logcat_timestamp(line)?;
        let (uid, pid, tid, level, tag, message) = Self::parse_logcat_body(remaining)?;
        Some(LogcatEvent {
            timestamp,
            uid,
            pid,
            tid,
            level,
            tag,
            message,
            section: section.to_string(),
            package_name: None,
        })
    }

    fn section_label(start_delimiter: &str) -> &'static str {
        if start_delimiter.contains("AFTER DONE") {
            "SYSTEM LOG AFTER DONE"
        } else {
            "SYSTEM LOG"
        }
    }

    fn parse_section(content: &str, start_delimiter: &str, end_suffix: &str) -> Vec<LogcatEvent> {
        let mut events = Vec::new();
        let Some(start_index) = content.find(start_delimiter) else {
            return events;
        };

        let section_start = start_index + start_delimiter.len();
        let remaining_content = &content[section_start..];
        let end_index = remaining_content
            .find("------ ")
            .and_then(|prefix_pos| {
                let after_prefix = &remaining_content[prefix_pos..];
                after_prefix
                    .find(end_suffix)
                    .map(|suffix_pos| section_start + prefix_pos + suffix_pos + end_suffix.len())
            })
            .unwrap_or(content.len());

        let section_content = &content[section_start..end_index];
        let label = Self::section_label(start_delimiter);

        for line in section_content.lines() {
            if events.len() >= MAX_EVENTS {
                break;
            }
            if let Some(ev) = Self::parse_line(line, label) {
                events.push(ev);
            }
        }

        events
    }
}

impl Parser for LogcatParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let sections = [
            (
                "------ SYSTEM LOG (logcat",
                " was the duration of 'SYSTEM LOG' ------",
            ),
            (
                "------ SYSTEM LOG AFTER DONE",
                " was the duration of 'SYSTEM LOG AFTER DONE' ------",
            ),
        ];

        let mut events = Vec::new();
        let mut by_section: HashMap<String, usize> = HashMap::new();

        for (start, end) in sections {
            let mut parsed = Self::parse_section(&content, start, end);
            let label = Self::section_label(start);
            *by_section.entry(label.to_string()).or_insert(0) += parsed.len();
            if events.len() + parsed.len() > MAX_EVENTS {
                let remaining = MAX_EVENTS.saturating_sub(events.len());
                parsed.truncate(remaining);
            }
            events.extend(parsed);
            if events.len() >= MAX_EVENTS {
                break;
            }
        }

        Ok(json!({
            "events": events,
            "total_events": events.len(),
            "sections": by_section,
            "truncated": events.len() >= MAX_EVENTS,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn parse_logcat_line_threadtime() {
        let line = "12-18 10:31:13.784  1017   684 16027 I keystore2: unlock ok";
        let ev = LogcatParser::parse_line(line, "SYSTEM LOG").unwrap();
        assert_eq!(ev.timestamp, "12-18 10:31:13.784");
        assert_eq!(ev.uid, 1017);
        assert_eq!(ev.pid, 684);
        assert_eq!(ev.tid, 16027);
        assert_eq!(ev.level, "I");
        assert_eq!(ev.tag, "keystore2");
        assert_eq!(ev.message, "unlock ok");
    }

    #[test]
    fn parse_system_log_section() {
        let data = b"------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n\
12-18 10:31:13.784 10133 1234 1234 I ExampleApp: started\n\
12-18 10:31:14.000  1000 5678 5678 W ActivityManager: slow operation\n\
------ 0.622s was the duration of 'SYSTEM LOG' ------\n";
        let parser = LogcatParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["tag"], "ExampleApp");
        assert_eq!(events[0]["uid"], 10133);
        assert_eq!(events[1]["level"], "W");
    }
}
