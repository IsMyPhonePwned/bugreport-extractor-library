use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;

/// A specialized parser for 'MEMORY INFO' sections in log files.
pub struct MemoryParser;

impl Default for MemoryParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Memory Parser")
    }
}

impl MemoryParser {
    /// Creates a new MemoryParser.
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(MemoryParser)
    }
}

impl Parser for MemoryParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut results = Vec::new();

        const START_DELIMITER: &str = "------ MEMORY INFO (/proc/meminfo) ------";
        const END_DELIMITER_PREFIX: &str = "------ ";

        // Look for multiple memory info blocks in a single file
        for block in content.split(START_DELIMITER).skip(1) {
            let mut memory_map = Map::new();

            // The content of the block is everything until the next '------' line.
            let lines = block.lines().take_while(|&line| !line.starts_with(END_DELIMITER_PREFIX));

            for line in lines {
                if let Some((key, value_str)) = line.split_once(':') {
                    let key = key.trim().to_string();
                    let value_trimmed = value_str.trim();

                    // Attempt to parse the numeric part of the value, ignoring "kB" or other text.
                    let numeric_value: Option<u64> = value_trimmed
                        .split_whitespace()
                        .next()
                        .and_then(|num_str| num_str.parse().ok());

                    if let Some(num) = numeric_value {
                        memory_map.insert(key, json!(num));
                    } else {
                        // If it's not a number, store it as a string.
                        memory_map.insert(key, json!(value_trimmed));
                    }
                }
            }

            if !memory_map.is_empty() {
                results.push(json!(memory_map));
            }
        }
        // Return a JSON array, as there might be multiple memory sections.
        Ok(json!(results))
    }
}