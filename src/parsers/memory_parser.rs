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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;
    use serde_json::json;

    #[test]
    fn test_parse_single_memory_block() {
        let data = b"
------ MEMORY INFO (/proc/meminfo) ------
MemTotal:       12126388 kB
MemFree:         1330080 kB
MemAvailable:    5913264 kB
RandomKey:      Some String Value
MalformedLine
------ END ------
        ";
        let parser = MemoryParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([
            {
                "MemTotal": 12126388,
                "MemFree": 1330080,
                "MemAvailable": 5913264,
                "RandomKey": "Some String Value"
            }
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_multiple_memory_blocks() {
        let data = b"
Junk before first block
------ MEMORY INFO (/proc/meminfo) ------
MemTotal:       1000 kB
MemFree:         500 kB
------ END ------
Some text in between
------ MEMORY INFO (/proc/meminfo) ------
MemTotal:       2000 kB
MemFree:        1500 kB
------ END ------
Junk after last block
        ";
        let parser = MemoryParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([
            {
                "MemTotal": 1000,
                "MemFree": 500,
            },
            {
                "MemTotal": 2000,
                "MemFree": 1500,
            }
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_no_memory_blocks() {
        let data = b"Some random data without any memory info blocks.";
        let parser = MemoryParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_empty_input() {
        let data = b"";
        let parser = MemoryParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_block_with_no_content() {
        let data = b"------ MEMORY INFO (/proc/meminfo) ------\n------ END ------";
        let parser = MemoryParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([]); // An empty map is created but not pushed to results.
        assert_eq!(result, expected);
    }
}