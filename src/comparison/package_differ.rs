use serde_json::Value;
use super::{ParserComparison, TimelineEvent};
use crate::parsers::ParserType;

/// Compare package parser outputs
pub fn compare_packages(before: &Value, after: &Value) -> ParserComparison {
    let mut comparison = ParserComparison::new(ParserType::Package);
    
    // Extract install logs from both
    let before_logs = extract_install_logs(before);
    let after_logs = extract_install_logs(after);
    
    // Create maps by package name for easy lookup
    let before_map: std::collections::HashMap<String, &Value> = before_logs.iter()
        .filter_map(|log| {
            log.get("pkg")
                .and_then(|p| p.as_str())
                .map(|pkg| (pkg.to_string(), *log))  // Dereference log here
        })
        .collect();
    
    let after_map: std::collections::HashMap<String, &Value> = after_logs.iter()
        .filter_map(|log| {
            log.get("pkg")
                .and_then(|p| p.as_str())
                .map(|pkg| (pkg.to_string(), *log))  // Dereference log here
        })
        .collect();
    
    // Find added packages
    for (pkg_name, log) in &after_map {
        if !before_map.contains_key(pkg_name) {
            comparison.added.push((*log).clone());
        }
    }
    
    // Find removed packages
    for (pkg_name, log) in &before_map {
        if !after_map.contains_key(pkg_name) {
            comparison.removed.push((*log).clone());
        }
    }
    
    // Find modified packages (same package, different version)
    for (pkg_name, after_log) in &after_map {
        if let Some(before_log) = before_map.get(pkg_name) {
            let before_version = before_log.get("versionCode");
            let after_version = after_log.get("versionCode");
            
            if before_version != after_version {
                comparison.modified.push(((*before_log).clone(), (*after_log).clone()));
            } else {
                comparison.unchanged_count += 1;
            }
        }
    }
    
    comparison
}

/// Extract timeline events from package comparison
pub fn extract_timeline_events(comparison: &ParserComparison) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    
    // Added packages
    for pkg in &comparison.added {
        if let Some(timestamp) = pkg.get("timestamp").and_then(|t| t.as_str()) {
            events.push(TimelineEvent {
                timestamp: timestamp.to_string(),
                parser: ParserType::Package,
                event_type: "package_installed".to_string(),
                change_type: "added".to_string(),
                details: pkg.clone(),
            });
        }
    }
    
    // Removed packages
    for pkg in &comparison.removed {
        if let Some(timestamp) = pkg.get("timestamp").and_then(|t| t.as_str()) {
            events.push(TimelineEvent {
                timestamp: timestamp.to_string(),
                parser: ParserType::Package,
                event_type: "package_removed".to_string(),
                change_type: "removed".to_string(),
                details: pkg.clone(),
            });
        }
    }
    
    // Modified packages
    for (_, after_pkg) in &comparison.modified {
        if let Some(timestamp) = after_pkg.get("timestamp").and_then(|t| t.as_str()) {
            events.push(TimelineEvent {
                timestamp: timestamp.to_string(),
                parser: ParserType::Package,
                event_type: "package_updated".to_string(),
                change_type: "modified".to_string(),
                details: after_pkg.clone(),
            });
        }
    }
    
    events
}

fn extract_install_logs(output: &Value) -> Vec<&Value> {
    output.as_array()
        .and_then(|arr| arr.get(0))
        .and_then(|obj| obj.get("install_logs"))
        .and_then(|logs| logs.as_array())
        .map(|arr| arr.iter().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compare_packages_added() {
        let before = json!([{"install_logs": [
            {"pkg": "com.example.app1", "versionCode": 100}
        ]}]);
        
        let after = json!([{"install_logs": [
            {"pkg": "com.example.app1", "versionCode": 100},
            {"pkg": "com.example.app2", "versionCode": 200}
        ]}]);
        
        let comparison = compare_packages(&before, &after);
        assert_eq!(comparison.added.len(), 1);
        assert_eq!(comparison.removed.len(), 0);
        assert_eq!(comparison.unchanged_count, 1);
    }

    #[test]
    fn test_compare_packages_modified() {
        let before = json!([{"install_logs": [
            {"pkg": "com.example.app1", "versionCode": 100}
        ]}]);
        
        let after = json!([{"install_logs": [
            {"pkg": "com.example.app1", "versionCode": 200}
        ]}]);
        
        let comparison = compare_packages(&before, &after);
        assert_eq!(comparison.modified.len(), 1);
    }
}