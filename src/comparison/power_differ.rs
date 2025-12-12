use serde_json::Value;
use super::{ParserComparison, TimelineEvent};
use crate::parsers::ParserType;

/// Compare power parser outputs
pub fn compare_power(before: &Value, after: &Value) -> ParserComparison {
    let mut comparison = ParserComparison::new(ParserType::Power);
    
    let before_events = extract_power_events(before);
    let after_events = extract_power_events(after);
    
    // Power events are timestamped, so we compare by timestamp + event_type
    let before_keys: std::collections::HashSet<String> = before_events.iter()
        .filter_map(event_key)
        .collect();
    
    let after_keys: std::collections::HashSet<String> = after_events.iter()
        .filter_map(event_key)
        .collect();
    
    // Find new power events
    for event in &after_events {
        if let Some(key) = event_key(event) {
            if !before_keys.contains(&key) {
                comparison.added.push(event.clone());
            }
        }
    }
    
    // Find removed power events (rare, but possible if logs rotate)
    for event in &before_events {
        if let Some(key) = event_key(event) {
            if !after_keys.contains(&key) {
                comparison.removed.push(event.clone());
            }
        }
    }
    
    // Count unchanged
    comparison.unchanged_count = before_keys.intersection(&after_keys).count();
    
    comparison
}

/// Extract timeline events from power comparison
pub fn extract_timeline_events(comparison: &ParserComparison) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    
    // New power events
    for event in &comparison.added {
        if let Some(timestamp) = event.get("timestamp").and_then(|t| t.as_str()) {
            let event_type = event.get("power_event_type")
                .and_then(|e| e.as_str())
                .unwrap_or("power_event");
            
            events.push(TimelineEvent {
                timestamp: timestamp.to_string(),
                parser: ParserType::Power,
                event_type: event_type.to_string(),
                change_type: "added".to_string(),
                details: event.clone(),
            });
        }
    }
    
    events
}

fn extract_power_events(output: &Value) -> Vec<Value> {
    output.as_array()
        .map(|arr| arr.iter().cloned().collect())
        .unwrap_or_default()
}

fn event_key(event: &Value) -> Option<String> {
    let timestamp = event.get("timestamp").and_then(|t| t.as_str())?;
    let event_type = event.get("power_event_type").and_then(|e| e.as_str())?;
    Some(format!("{}:{}", timestamp, event_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compare_power_new_events() {
        let before = json!([
            {"timestamp": "2025-03-28 10:00:00", "power_event_type": "SHUTDOWN"}
        ]);
        
        let after = json!([
            {"timestamp": "2025-03-28 10:00:00", "power_event_type": "SHUTDOWN"},
            {"timestamp": "2025-03-28 12:00:00", "power_event_type": "REBOOT"}
        ]);
        
        let comparison = compare_power(&before, &after);
        assert_eq!(comparison.added.len(), 1);
        assert_eq!(comparison.removed.len(), 0);
        assert_eq!(comparison.unchanged_count, 1);
    }
}