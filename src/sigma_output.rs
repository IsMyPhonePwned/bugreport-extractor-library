use sigma_zero::models::RuleMatch;
use serde_json;

/// Determines if a rule match should be output based on minimum level filter
pub fn should_output_match(rule_match: &RuleMatch, min_level: &Option<String>) -> bool {
    if let Some(ref min) = min_level {
        if let Some(ref level) = rule_match.level {
            return level_priority(level) >= level_priority(min);
        }
        return false;
    }
    true
}

/// Returns the numeric priority for a severity level
fn level_priority(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Outputs a rule match in the specified format
/// 
/// Note: RuleMatch from sigma-zero contains a matched_log field of type LogEntry.
/// If populated, it contains the log entry that triggered the match. 
/// The function serializes it to JSON to extract and display relevant fields.
pub fn output_match(rule_match: &RuleMatch, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(rule_match) {
                println!("{}", json);
            }
        }
        "silent" => {
            // No output, just count
        }
        _ => {
            // Text format (default)
            let level = rule_match.level.as_deref().unwrap_or("unknown");
            let level_icon = match level {
                "critical" => "🔥",
                "high" => "🚨",
                "medium" => "⚠️ ",
                "low" => "ℹ️ ",
                _ => "• ",
            };
            
            println!(
                "{} [{}] {} ({})", 
                level_icon,
                level.to_uppercase(),
                rule_match.rule_title,
                rule_match.rule_id.as_deref().unwrap_or("unknown")
            );
            
            // Display matched log details if available
            // Serialize matched_log to JSON and display it
            if let Ok(log_json) = serde_json::to_value(&rule_match.matched_log) {
                // Try to extract common fields
                if let Some(obj) = log_json.as_object() {
                    if !obj.is_empty() {
                        if let Some(pkg) = obj.get("pkg").and_then(|v| v.as_str()) {
                            println!("  Package: {}", pkg);
                        }
                        if let Some(event_type) = obj.get("event_type").and_then(|v| v.as_str()) {
                            println!("  Event Type: {}", event_type);
                        }
                        if let Some(timestamp) = obj.get("timestamp").and_then(|v| v.as_str()) {
                            println!("  Timestamp: {}", timestamp);
                        }
                        if let Some(pid) = obj.get("pid") {
                            println!("  PID: {}", pid);
                        }
                        if let Some(cmd) = obj.get("cmd").and_then(|v| v.as_str()) {
                            println!("  Command: {}", cmd);
                        }
                    }
                }
            }
        }
    }
}

/// Statistics for Sigma rule evaluation
#[derive(Debug, Default)]
pub struct SigmaStats {
    pub total_logs_evaluated: usize,
    pub total_matches: usize,
    pub matches_by_level: std::collections::HashMap<String, usize>,
    pub matches_by_parser: std::collections::HashMap<String, usize>,
}

impl SigmaStats {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn record_match(&mut self, rule_match: &RuleMatch, parser_name: &str) {
        self.total_matches += 1;
        
        if let Some(ref level) = rule_match.level {
            *self.matches_by_level.entry(level.clone()).or_insert(0) += 1;
        }
        
        *self.matches_by_parser.entry(parser_name.to_string()).or_insert(0) += 1;
    }
    
    pub fn print_summary(&self) {
        println!("\n=== Sigma Detection Summary ===");
        println!("Total log entries evaluated: {}", self.total_logs_evaluated);
        println!("Total matches found: {}", self.total_matches);
        
        if !self.matches_by_level.is_empty() {
            println!("\nMatches by severity:");
            let mut levels: Vec<_> = self.matches_by_level.iter().collect();
            levels.sort_by_key(|(level, _)| std::cmp::Reverse(level_priority(level)));
            
            for (level, count) in levels {
                println!("  {}: {}", level.to_uppercase(), count);
            }
        }
        
        if !self.matches_by_parser.is_empty() {
            println!("\nMatches by parser:");
            let mut parsers: Vec<_> = self.matches_by_parser.iter().collect();
            parsers.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            
            for (parser, count) in parsers {
                println!("  {}: {}", parser, count);
            }
        }
        println!("===============================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_priority() {
        assert!(level_priority("critical") > level_priority("high"));
        assert!(level_priority("high") > level_priority("medium"));
        assert!(level_priority("medium") > level_priority("low"));
        assert!(level_priority("low") > level_priority("unknown"));
    }

    #[test]
    fn test_sigma_stats_basic() {
        let mut stats = SigmaStats::new();
        stats.total_logs_evaluated = 100;
        
        // Manually increment counters without needing RuleMatch objects
        stats.total_matches = 3;
        stats.matches_by_level.insert("critical".to_string(), 2);
        stats.matches_by_level.insert("high".to_string(), 1);
        stats.matches_by_parser.insert("Package".to_string(), 2);
        stats.matches_by_parser.insert("Process".to_string(), 1);
        
        assert_eq!(stats.total_matches, 3);
        assert_eq!(*stats.matches_by_level.get("critical").unwrap(), 2);
        assert_eq!(*stats.matches_by_level.get("high").unwrap(), 1);
        assert_eq!(*stats.matches_by_parser.get("Package").unwrap(), 2);
        assert_eq!(*stats.matches_by_parser.get("Process").unwrap(), 1);
    }
}