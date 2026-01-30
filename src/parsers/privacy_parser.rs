use super::Parser;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::error::Error;

/// A specialized parser for privacy-related information (GPS location, etc.)
pub struct PrivacyParser {
    coordinates_regex: Regex,
}

impl Default for PrivacyParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Privacy Parser")
    }
}

impl PrivacyParser {
    /// Creates a new PrivacyParser with compiled regexes
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Regex to parse coordinates like: {fused, 52.392128,4.902320±14.69m, ...}
        let coordinates_regex = Regex::new(
            r"\{([^,]+),\s*(-?\d+\.\d+),(-?\d+\.\d+)±([^,]+),?\s*(.*)?\}"
        )?;
        
        Ok(PrivacyParser {
            coordinates_regex,
        })
    }

    /// Parse a location request line
    /// Example: "10251/com.google.android.gms[.personalsafety]/d0c7b187 (FINE) Request[@10m BALANCED_POWER_ACCURACY, ...]"
    fn parse_location_listener(&self, line: &str) -> Option<Value> {
        let line = line.trim();
        
        // Extract UID/package/identifier and accuracy
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }
        
        let mut listener_map = Map::new();
        
        // Parse "10251/com.google.android.gms[.personalsafety]/d0c7b187"
        if let Some(identifier_part) = parts.first() {
            let id_parts: Vec<&str> = identifier_part.split('/').collect();
            
            if let Some(uid_str) = id_parts.first() {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    listener_map.insert("uid".to_string(), json!(uid));
                }
            }
            
            if id_parts.len() >= 2 {
                let package = id_parts[1];
                // Extract package name (might have [component] suffix)
                if let Some(bracket_pos) = package.find('[') {
                    let pkg_name = &package[..bracket_pos];
                    let component = &package[bracket_pos+1..package.len()-1];
                    listener_map.insert("package".to_string(), json!(pkg_name));
                    listener_map.insert("component".to_string(), json!(component));
                } else {
                    listener_map.insert("package".to_string(), json!(package));
                }
            }
            
            if id_parts.len() >= 3 {
                listener_map.insert("listener_id".to_string(), json!(id_parts[2]));
            }
        }
        
        // Parse accuracy level like "(FINE)" or "(COARSE)"
        for part in &parts {
            if part.starts_with('(') && part.ends_with(')') {
                let accuracy = &part[1..part.len()-1];
                listener_map.insert("accuracy".to_string(), json!(accuracy));
                break;
            }
        }
        
        // Parse Request details
        if let Some(request_start) = line.find("Request[") {
            let request_str = &line[request_start..];
            if let Some(end) = request_str.find(']') {
                let request_content = &request_str[8..end+1]; // "Request[" is 8 chars
                listener_map.insert("request".to_string(), json!(self.parse_location_request(request_content)));
            }
        }
        
        Some(json!(listener_map))
    }

    /// Parse location request details
    /// Example: "@10m BALANCED_POWER_ACCURACY, minUpdateInterval=2m, minUpdateDistance=40.0, THROTTLE_NEVER, WorkSource{10251 com.google.android.gms}"
    fn parse_location_request(&self, request_str: &str) -> Map<String, Value> {
        let mut request_map = Map::new();
        
        // Parse interval/accuracy at the beginning (e.g., "@10m BALANCED_POWER_ACCURACY" or "PASSIVE/106751991167d7h12m55s807ms")
        let parts: Vec<&str> = request_str.split(',').map(|s| s.trim()).collect();
        
        if let Some(first_part) = parts.first() {
            let tokens: Vec<&str> = first_part.split_whitespace().collect();
            
            // Check if first token is an interval (starts with @ or contains /)
            if let Some(first_token) = tokens.first() {
                if first_token.starts_with('@') {
                    request_map.insert("interval".to_string(), json!(&first_token[1..]));
                } else if first_token.contains('/') {
                    let sub_parts: Vec<&str> = first_token.split('/').collect();
                    if let Some(mode) = sub_parts.first() {
                        request_map.insert("mode".to_string(), json!(mode));
                    }
                    if sub_parts.len() > 1 {
                        request_map.insert("duration".to_string(), json!(sub_parts[1]));
                    }
                }
            }
            
            // Look for accuracy level
            for token in tokens.iter().skip(1) {
                if token.contains("ACCURACY") || token.contains("POWER") {
                    request_map.insert("quality".to_string(), json!(token));
                    break;
                }
            }
        }
        
        // Parse other parameters
        for part in parts.iter().skip(1) {
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                request_map.insert(key.to_string(), json!(value));
            } else if part.contains("THROTTLE") || part.contains("bypass") {
                request_map.insert("flags".to_string(), json!(part));
            } else if part.starts_with("WorkSource{") {
                // Parse WorkSource{10251 com.google.android.gms}
                if let Some(ws_end) = part.find('}') {
                    let ws_content = &part[11..ws_end]; // "WorkSource{" is 11 chars
                    let ws_parts: Vec<&str> = ws_content.split_whitespace().collect();
                    
                    let mut ws_map = Map::new();
                    if let Some(uid_str) = ws_parts.first() {
                        if let Ok(uid) = uid_str.parse::<u32>() {
                            ws_map.insert("uid".to_string(), json!(uid));
                        }
                    }
                    if ws_parts.len() > 1 {
                        ws_map.insert("package".to_string(), json!(ws_parts[1]));
                    }
                    request_map.insert("work_source".to_string(), json!(ws_map));
                }
            }
        }
        
        request_map
    }

    /// Parse GPS coordinates
    /// Example: {fused, 52.392128,4.902320±14.69m, alt=63.4±171.19m, spd=.0±2.29m/s, ert=11-08 22:18:14.822}
    fn parse_location_coordinates(&self, location_str: &str) -> Option<Map<String, Value>> {
        if let Some(caps) = self.coordinates_regex.captures(location_str) {
            let mut loc_map = Map::new();
            
            // Provider (e.g., "fused")
            if let Some(provider) = caps.get(1) {
                loc_map.insert("provider".to_string(), json!(provider.as_str()));
            }
            
            // Latitude
            if let Some(lat) = caps.get(2) {
                if let Ok(lat_val) = lat.as_str().parse::<f64>() {
                    loc_map.insert("latitude".to_string(), json!(lat_val));
                }
            }
            
            // Longitude
            if let Some(lon) = caps.get(3) {
                if let Ok(lon_val) = lon.as_str().parse::<f64>() {
                    loc_map.insert("longitude".to_string(), json!(lon_val));
                }
            }
            
            // Accuracy
            if let Some(acc) = caps.get(4) {
                loc_map.insert("accuracy".to_string(), json!(acc.as_str()));
            }
            
            // Additional details (altitude, speed, time)
            if let Some(details) = caps.get(5) {
                let details_str = details.as_str();
                for part in details_str.split(',') {
                    let part = part.trim();
                    if let Some((key, value)) = part.split_once('=') {
                        loc_map.insert(key.to_string(), json!(value));
                    }
                }
            }
            
            return Some(loc_map);
        }
        
        None
    }

    /// Parse Fused Location Provider section
    fn parse_location_provider_section(&self, section: &str) -> Option<Value> {
        let lines: Vec<&str> = section.lines().collect();
        let mut provider_map = Map::new();
        
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();
            
            // Check for "Fused Location Provider:"
            if line.contains("Fused Location Provider:") || line.contains("Location Provider:") {
                provider_map.insert("type".to_string(), json!("fused_location_provider"));
                i += 1;
                continue;
            }
            
            // Parse source
            if line.starts_with("source:") {
                if let Some(request_start) = line.find("Request[") {
                    let request_str = &line[request_start+8..];
                    if let Some(end) = request_str.find(']') {
                        let request_content = &request_str[..end];
                        provider_map.insert("source".to_string(), json!(self.parse_location_request(request_content)));
                    }
                }
                i += 1;
                continue;
            }
            
            // Parse listeners
            if line.starts_with("listeners:") {
                let mut listeners = Vec::new();
                i += 1;
                
                // Read all listener lines (they are indented)
                while i < lines.len() {
                    let listener_line = lines[i];
                    // Check if line is indented (part of listeners)
                    if listener_line.starts_with("        ") || listener_line.starts_with("\t\t") {
                        if let Some(listener) = self.parse_location_listener(listener_line) {
                            listeners.push(listener);
                        }
                        i += 1;
                    } else {
                        break;
                    }
                }
                
                if !listeners.is_empty() {
                    provider_map.insert("listeners".to_string(), json!(listeners));
                }
                continue;
            }
            
            // Parse last availability
            if line.starts_with("last availability:") {
                if let Some(value) = line.split(':').nth(1) {
                    let availability = value.trim() == "true";
                    provider_map.insert("last_availability".to_string(), json!(availability));
                }
                i += 1;
                continue;
            }
            
            // Parse last location (fine)
            if line.starts_with("last location (fine):") {
                if let Some(loc_start) = line.find('{') {
                    let loc_str = &line[loc_start..];
                    if let Some(location) = self.parse_location_coordinates(loc_str) {
                        provider_map.insert("last_location_fine".to_string(), json!(location));
                    }
                }
                i += 1;
                continue;
            }
            
            // Parse last location (coarse)
            if line.starts_with("last location (coarse):") {
                if let Some(loc_start) = line.find('{') {
                    let loc_str = &line[loc_start..];
                    if let Some(location) = self.parse_location_coordinates(loc_str) {
                        provider_map.insert("last_location_coarse".to_string(), json!(location));
                    }
                }
                i += 1;
                continue;
            }
            
            i += 1;
        }
        
        if !provider_map.is_empty() {
            Some(json!(provider_map))
        } else {
            None
        }
    }
}

impl Parser for PrivacyParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut results = Vec::new();
        
        // Look for Fused Location Provider sections
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i];
            
            // Check for location provider section
            if line.contains("Fused Location Provider:") || line.contains("Location Provider:") {
                // Collect the entire section (until we hit a non-indented line or end)
                let section_start = i;
                i += 1;
                
                // Find the end of this section
                while i < lines.len() {
                    let current_line = lines[i];
                    // Section ends when we hit a line that's not indented or is another section header
                    if !current_line.starts_with(' ') && !current_line.starts_with('\t') && !current_line.is_empty() {
                        break;
                    }
                    i += 1;
                }
                
                // Parse the section
                let section = lines[section_start..i].join("\n");
                if let Some(provider_data) = self.parse_location_provider_section(&section) {
                    results.push(provider_data);
                }
                
                continue;
            }
            
            i += 1;
        }
        
        Ok(json!({
            "privacy": {
                "location_providers": results
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_location_provider() {
        let data = r"
    Fused Location Provider:
      source: Request[@10m BALANCED_POWER_ACCURACY, WorkSource{10251 com.google.android.gms}]
      listeners:
        10251/com.google.android.gms[.personalsafety]/d0c7b187 (FINE) Request[@10m BALANCED_POWER_ACCURACY, minUpdateInterval=2m, minUpdateDistance=40.0, THROTTLE_NEVER, WorkSource{10251 com.google.android.gms}]
        10251/com.google.android.gms[earthquake_alerting]/ef007be (FINE) Request[@30m BALANCED_POWER_ACCURACY, minUpdateInterval=5m, minUpdateDistance=1000.0, THROTTLE_NEVER, WorkSource{10251 com.google.android.gms}]
        5013/com.sec.location.nsflp2/d8d75c93 (FINE) Request[PASSIVE/106751991167d7h12m55s807ms, minUpdateInterval=0s, maxUpdateAge=0s, WorkSource{5013 com.sec.location.nsflp2}]
      last availability: false
      last location (fine): {fused, 12.345678,98.765432±14.69m, alt=100.0±50.0m, spd=.0±2.29m/s, ert=01-01 12:00:00.000}
      last location (coarse): {fused, 12.340000,98.760000±2000.0m, ert=01-01 12:00:00.000}
".as_bytes();
        
        let parser = PrivacyParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Verify the structure
        assert!(result.get("privacy").is_some());
        let privacy = result["privacy"].as_object().unwrap();
        assert!(privacy.get("location_providers").is_some());
        
        let providers = privacy["location_providers"].as_array().unwrap();
        assert_eq!(providers.len(), 1);
        
        let provider = &providers[0];
        assert_eq!(provider["type"], "fused_location_provider");
        
        // Check listeners
        let listeners = provider["listeners"].as_array().unwrap();
        assert_eq!(listeners.len(), 3);
        
        // Check first listener
        let listener1 = &listeners[0];
        assert_eq!(listener1["uid"], 10251);
        assert_eq!(listener1["package"], "com.google.android.gms");
        assert_eq!(listener1["component"], ".personalsafety");
        assert_eq!(listener1["accuracy"], "FINE");
        
        // Check last location (fine)
        let last_loc_fine = provider["last_location_fine"].as_object().unwrap();
        assert_eq!(last_loc_fine["provider"], "fused");
        assert_eq!(last_loc_fine["latitude"], 12.345678);
        assert_eq!(last_loc_fine["longitude"], 98.765432);
        assert_eq!(last_loc_fine["accuracy"], "14.69m");
        
        // Check last location (coarse)
        let last_loc_coarse = provider["last_location_coarse"].as_object().unwrap();
        assert_eq!(last_loc_coarse["latitude"], 12.340000);
        assert_eq!(last_loc_coarse["longitude"], 98.760000);
    }
}
