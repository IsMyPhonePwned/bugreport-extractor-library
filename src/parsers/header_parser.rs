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
