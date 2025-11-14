use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;

/// A specialized parser for 'CHECKIN BATTERYSTATS' sections in log files.
pub struct BatteryParser;

impl Default for BatteryParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Battery Parser")
    }
}

impl BatteryParser {
    /// Creates a new BatteryParser.
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(BatteryParser)
    }

    /// Parses a "9,hsp,..." line.
    /// Example: 9,hsp,0,1010350,"net.pradeo.edfservice.intune"
    fn parse_hsp_line(parts: &[&str]) -> Value {
        if parts.len() < 5 {
            return json!(parts.join(",")); // Fallback
        }
        
        json!({
            "type": "hsp",
            "index": parts[2].parse::<u32>().ok(),
            "uid": parts[3].parse::<u32>().ok(),
            "name": parts[4].trim_matches('"')
        })
    }

    /// Parses a "9,0,i,vers,..." line.
    /// Example: 9,0,i,vers,36,1179860,UP1A.231005.007,UP1A.231005.007
    fn parse_version_line(parts: &[&str]) -> Value {
        if parts.len() < 8 {
            return json!(parts.join(",")); // Fallback
        }

        json!({
            "type": "version",
            "version_code": parts[4].parse::<u32>().ok(),
            "sdk_version": parts[5].parse::<u32>().ok(),
            "build_number_1": parts[6],
            "build_number_2": parts[7]
        })
    }
}

impl Parser for BatteryParser {
    /// Corrected function signature: data: &[u8]
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut results = Vec::new();

        const START_DELIMITER_PREFIX: &str = "------ CHECKIN BATTERYSTATS (";
        const END_DELIMITER_PREFIX: &str = "------ ";

        for block in content.split(START_DELIMITER_PREFIX).skip(1) {
            let mut section_map = Map::new();
            let mut hsp_records = Vec::new();
            let mut other_records = Vec::new();

            if let Some((_header_line, block_content)) = block.split_once('\n') {
                let lines = block_content
                    .lines()
                    .take_while(|&line| !line.starts_with(END_DELIMITER_PREFIX));

                for line in lines {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    // Split into a maximum of 5 parts to handle the "name" field containing commas
                    let parts: Vec<&str> = line.splitn(5, ',').collect();
                    if parts.len() < 2 {
                        other_records.push(json!(line));
                        continue;
                    }
                    
                    match parts[1] {
                        "hsp" => hsp_records.push(Self::parse_hsp_line(&parts)),
                        "0" if parts.get(2) == Some(&"i") && parts.get(3) == Some(&"vers") => {
                             // Re-split for the full line, as version has more parts
                            let all_parts: Vec<&str> = line.split(',').collect();
                            section_map.insert("version_info".to_string(), Self::parse_version_line(&all_parts));
                        },
                        _ => other_records.push(json!(line))
                    }
                }
            }

            if !hsp_records.is_empty() {
                section_map.insert("hsp_records".to_string(), json!(hsp_records));
            }
            if !other_records.is_empty() {
                section_map.insert("other_records".to_string(), json!(other_records));
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
    fn test_parse_battery_stats_block() {
        let data = b"
Junk before
------ CHECKIN BATTERYSTATS (/system/bin/dumpsys -T 30000 batterystats -c) ------
9,0,i,vers,36,1179860,UP1A.231005.007,UP1A.231005.007
9,hsp,0,1010350,\"net.xxx.yyy.zzz\"
9,hsp,1,1010331,\"com.azure.authenticator\"
9,hsp,2,0,\"0\"
9,h,0:RESET:TIME:1743093423227
------ MEMORY INFO (/proc/meminfo) ------
MemTotal:       12126388 kB
        ";
        let parser = BatteryParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let expected = json!([
            {
                "version_info": {
                    "type": "version",
                    "version_code": 36,
                    "sdk_version": 1179860,
                    "build_number_1": "UP1A.231005.007",
                    "build_number_2": "UP1A.231005.007"
                },
                "hsp_records": [
                    {
                        "type": "hsp",
                        "index": 0,
                        "uid": 1010350,
                        "name": "net.xxx.yyy.zzz"
                    },
                    {
                        "type": "hsp",
                        "index": 1,
                        "uid": 1010331,
                        "name": "com.azure.authenticator"
                    },
                    {
                        "type": "hsp",
                        "index": 2,
                        "uid": 0,
                        "name": "0"
                    }
                ],
                "other_records": [
                    "9,h,0:RESET:TIME:1743093423227"
                ]
            }
        ]);
        assert_eq!(result, expected);
    }
}