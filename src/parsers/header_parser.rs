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
        let delimiter = "\n========================================================\n== dumpstate: ";

        let captures: Vec<Value> = content
            .split(delimiter)
            .skip(1) // The first chunk is everything before the first dumpstate, so we skip it.
            .map(|section| {
                // The section now starts with the title, e.g., "2025-09-11 10:35:38\n========================================================\n\nBuild:..."
                // We split this into the title line and the rest of the content.
                let (title_line, rest) = section
                    .split_once("\n========================================================\n\n")
                    .unwrap_or((section, "")); // Fallback if the second part of header is missing

                // The content block is terminated by the next section header `------ ` or end of file.
                // We take everything before the next header.
                let content_block = rest.split("\n------ ").next().unwrap_or("").trim();

                let lines: Vec<&str> = content_block.lines().collect();

                json!({
                    "section_title": title_line.trim(),
                    "content_lines": lines,
                })
            })
            .collect();

        // Return a JSON array, where each element is a parsed dumpstate section.
        Ok(json!(captures))
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
        let expected = json!([
            {
                "section_title": "2025-10-22 09:30:00",
                "content_lines": [
                    "Build: XYZ",
                    "Line 2",
                    "Line 3"
                ]
            }
        ]);
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
        let expected = json!([
            {
                "section_title": "2025-10-22 09:30:00",
                "content_lines": [
                    "Content 1",
                    "Line 2"
                ]
            },
            {
                "section_title": "2025-10-22 09:35:00",
                "content_lines": [
                    "Content 2",
                    "Line B"
                ]
            }
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_no_headers() {
        let data = b"This is a file with no dumpstate headers.";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_empty_input() {
        let data = b"";
        let parser = HeaderParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([]);
        assert_eq!(result, expected);
    }
}