use serde_json::Value;
use super::{ParserComparison, TimelineEvent};
use crate::parsers::ParserType;
use std::collections::HashSet;

/// Compare process parser outputs
pub fn compare_processes(before: &Value, after: &Value) -> ParserComparison {
    let mut comparison = ParserComparison::new(ParserType::Process);
    
    let before_procs = extract_processes(before);
    let after_procs = extract_processes(after);
    
    // Create sets of command names (PIDs will differ, so we compare by command)
    let before_cmds: HashSet<String> = before_procs.iter()
        .filter_map(|p| p.get("cmd").and_then(|c| c.as_str()).map(String::from))
        .collect();
    
    let after_cmds: HashSet<String> = after_procs.iter()
        .filter_map(|p| p.get("cmd").and_then(|c| c.as_str()).map(String::from))
        .collect();
    
    // Find new processes (command not in before)
    for proc in &after_procs {
        if let Some(cmd) = proc.get("cmd").and_then(|c| c.as_str()) {
            if !before_cmds.contains(cmd) {
                comparison.added.push(proc.clone());
            }
        }
    }
    
    // Find stopped processes (command not in after)
    for proc in &before_procs {
        if let Some(cmd) = proc.get("cmd").and_then(|c| c.as_str()) {
            if !after_cmds.contains(cmd) {
                comparison.removed.push(proc.clone());
            }
        }
    }
    
    // Count unchanged (commands in both)
    comparison.unchanged_count = before_cmds.intersection(&after_cmds).count();
    
    comparison
}

/// Extract timeline events from process comparison
pub fn extract_timeline_events(comparison: &ParserComparison) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    
    // New processes - use current time as we don't have exact start time
    for proc in &comparison.added {
        events.push(TimelineEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            parser: ParserType::Process,
            event_type: "process_started".to_string(),
            change_type: "added".to_string(),
            details: proc.clone(),
        });
    }
    
    // Stopped processes
    for proc in &comparison.removed {
        events.push(TimelineEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            parser: ParserType::Process,
            event_type: "process_stopped".to_string(),
            change_type: "removed".to_string(),
            details: proc.clone(),
        });
    }
    
    events
}

fn extract_processes(output: &Value) -> Vec<Value> {
    output.as_array()
        .map(|arr| arr.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compare_processes_new() {
        let before = json!([
            {"pid": 100, "cmd": "system_server"},
            {"pid": 101, "cmd": "surfaceflinger"}
        ]);
        
        let after = json!([
            {"pid": 200, "cmd": "system_server"},
            {"pid": 201, "cmd": "surfaceflinger"},
            {"pid": 202, "cmd": "suspicious_binary"}
        ]);
        
        let comparison = compare_processes(&before, &after);
        assert_eq!(comparison.added.len(), 1);
        assert_eq!(comparison.removed.len(), 0);
        assert_eq!(comparison.unchanged_count, 2);
    }

    #[test]
    fn test_compare_processes_stopped() {
        let before = json!([
            {"pid": 100, "cmd": "system_server"},
            {"pid": 101, "cmd": "old_process"}
        ]);
        
        let after = json!([
            {"pid": 200, "cmd": "system_server"}
        ]);
        
        let comparison = compare_processes(&before, &after);
        assert_eq!(comparison.removed.len(), 1);
        assert_eq!(comparison.unchanged_count, 1);
    }
}