use super::Parser;
use serde_json::{json, Value};
use std::error::Error;

/// A specialized parser for 'dumpstate' header in log files.
pub struct HeaderParser {
}

impl Default for HeaderParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Header Parser")
    }
}

impl HeaderParser {
    /// Creates a new HeaderParser
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(HeaderParser {})
    }
}

impl Parser for HeaderParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);

        // Using string splitting is significantly faster than a backtracking regex for this task.
        // We first split the entire file into potential sections based on the "== dumpstate:" header.
        // Handle both cases: header at start of file (no leading newline) and header in middle of file
        let delimiter = "========================================================\n== dumpstate: ";

        // Normalize: ensure we can split consistently by adding a marker if it starts at file beginning
        let normalized_content = if content.starts_with(delimiter) {
            format!("\n{}", content)
        } else {
            content.to_string()
        };
        
        let delimiter_with_newline = format!("\n{}", delimiter);
        
        // Find the first dumpstate section (there's typically only one)
        let first_section = normalized_content
            .split(&delimiter_with_newline)
            .skip(1) // The first chunk is everything before the first dumpstate, so we skip it.
            .next();
        
        let result = if let Some(section) = first_section {
            // The section now starts with the title (timestamp), e.g., "2025-09-11 10:35:38\n========================================================\n\nBuild:..."
                // We split this into the title line and the rest of the content.
                let (title_line, rest) = section
                    .split_once("\n========================================================\n\n")
                    .unwrap_or((section, "")); // Fallback if the second part of header is missing

                // The content block is terminated by the next section header `------ ` or end of file.
                // We take everything before the next header.
                let content_block = rest.split("\n------ ").next().unwrap_or("").trim();

            // Parse key-value pairs from the content lines
            let mut result_map = serde_json::Map::new();
            
            // Store the timestamp
            result_map.insert("timestamp".to_string(), json!(title_line.trim()));
            
            let mut other_lines = Vec::new();
            
            for line in content_block.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                
                // Try to split on ": " to extract key-value pairs
                if let Some((key, value)) = trimmed.split_once(": ") {
                    let key = key.trim();
                    let value = value.trim();
                    // Only add if key is not empty and doesn't already exist
                    if !key.is_empty() {
                        result_map.insert(key.to_string(), json!(value));
                    }
                } else {
                    // Line doesn't match key-value pattern, store it separately
                    other_lines.push(trimmed);
                }
            }
            
            // Add other_lines only if there are any
            if !other_lines.is_empty() {
                result_map.insert("other_lines".to_string(), json!(other_lines));
            }

            Value::Object(result_map)
        } else {
            // No dumpstate section found, return an empty object
            json!({})
        };

        // Return a single JSON object with the timestamp and all key-value pairs
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;
    use serde_json::json;

    #[test]
    fn test_parse_single_header() {
        let data = b"
========================================================
== dumpstate: 2025-10-22 09:30:00
========================================================

Build: XYZ
Line 2
Line 3
------ next section ------
        ";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!({
            "timestamp": "2025-10-22 09:30:00",
            "Build": "XYZ",
            "other_lines": ["Line 2", "Line 3"]
        });
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_multiple_headers() {
        let data = b"
Junk before
========================================================
== dumpstate: 2025-10-22 09:30:00
========================================================

Content 1
Line 2
========================================================
== dumpstate: 2025-10-22 09:35:00
========================================================

Content 2
Line B
------ next section ------
Junk after
        ";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        // When multiple headers exist, we take the first one
        let expected = json!({
            "timestamp": "2025-10-22 09:30:00",
            "other_lines": ["Content 1", "Line 2"]
        });
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_no_headers() {
        let data = b"This is a file with no dumpstate headers.";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!({});
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_empty_input() {
        let data = b"";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!({});
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_real_world_format() {
        let data = b"========================================================
== dumpstate: 2025-11-09 09:32:54
========================================================

Build: UP1A.231005.007.A346BXXS9CYD1
Build fingerprint: 'samsung/a34xeea/a34x:14/UP1A.231005.007/A346BXXS9CYD1:user/release-keys'
Bootloader: A346BXXS9CYD1
Radio: A346BXXS9CYD1,A346BXXS9CYD1
Network: NL KPN,
Module Metadata version: 360969444
Android SDK version: 34
SDK extensions: [ad_services=11, r=11, s=11, t=11, u=11]
Kernel: Linux version 4.19.191-28577532-abA346BXXS9CYD1
Command line: console=tty0 console=ttyS0,921600n1
Bootconfig: *** Error dumping /proc/bootconfig: No such file or directory
Uptime: up 0 weeks, 0 days, 16 hours, 17 minutes,  load average: 32.50, 32.55, 31.26
Bugreport format version: 2.0
Dumpstate info: id=6 pid=30572 dry_run=0 parallel_run=1 args=/system/bin/dumpstate -S -d bugreport_mode=BUGREPORT_DEFAULT
------ next section ------
        ";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Verify it's an object with the timestamp and key-value pairs
        assert!(result.is_object());
        assert_eq!(result["timestamp"], "2025-11-09 09:32:54");
        assert_eq!(result["Build"], "UP1A.231005.007.A346BXXS9CYD1");
        assert_eq!(result["Build fingerprint"], "'samsung/a34xeea/a34x:14/UP1A.231005.007/A346BXXS9CYD1:user/release-keys'");
        assert_eq!(result["Bootloader"], "A346BXXS9CYD1");
        assert_eq!(result["Radio"], "A346BXXS9CYD1,A346BXXS9CYD1");
        assert_eq!(result["Network"], "NL KPN,");
        assert_eq!(result["Module Metadata version"], "360969444");
        assert_eq!(result["Android SDK version"], "34");
        assert_eq!(result["SDK extensions"], "[ad_services=11, r=11, s=11, t=11, u=11]");
        assert_eq!(result["Bugreport format version"], "2.0");
    }
}