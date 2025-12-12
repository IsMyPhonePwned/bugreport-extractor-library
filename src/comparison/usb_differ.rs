use serde_json::Value;
use super::{ParserComparison, TimelineEvent};
use crate::parsers::ParserType;

/// Compare USB parser outputs
pub fn compare_usb(before: &Value, after: &Value) -> ParserComparison {
    let mut comparison = ParserComparison::new(ParserType::Usb);
    
    let before_devices = extract_usb_devices(before);
    let after_devices = extract_usb_devices(after);
    
    // Compare by vendor_id + product_id
    let before_ids: std::collections::HashSet<String> = before_devices.iter()
        .filter_map(|device| device_id(*device))  // Dereference &&Value to &Value
        .collect();
    
    let after_ids: std::collections::HashSet<String> = after_devices.iter()
        .filter_map(|device| device_id(*device))  // Dereference &&Value to &Value
        .collect();
    
    // Find newly connected devices
    for device in &after_devices {
        if let Some(id) = device_id(device) {
            if !before_ids.contains(&id) {
                comparison.added.push((*device).clone());  // Dereference before cloning
            }
        }
    }
    
    // Find disconnected devices
    for device in &before_devices {
        if let Some(id) = device_id(device) {
            if !after_ids.contains(&id) {
                comparison.removed.push((*device).clone());  // Dereference before cloning
            }
        }
    }
    
    // Count unchanged
    comparison.unchanged_count = before_ids.intersection(&after_ids).count();
    
    comparison
}

/// Extract timeline events from USB comparison
pub fn extract_timeline_events(comparison: &ParserComparison) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    
    // Connected devices
    for device in &comparison.added {
        events.push(TimelineEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            parser: ParserType::Usb,
            event_type: "usb_connected".to_string(),
            change_type: "added".to_string(),
            details: device.clone(),
        });
    }
    
    // Disconnected devices
    for device in &comparison.removed {
        events.push(TimelineEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            parser: ParserType::Usb,
            event_type: "usb_disconnected".to_string(),
            change_type: "removed".to_string(),
            details: device.clone(),
        });
    }
    
    events
}

fn extract_usb_devices(output: &Value) -> Vec<&Value> {
    output.as_array()
        .and_then(|arr| arr.get(0))
        .and_then(|obj| obj.get("connected_devices"))
        .and_then(|devices| devices.as_array())
        .map(|arr| arr.iter().collect())
        .unwrap_or_default()
}

fn device_id(device: &Value) -> Option<String> {
    let vid = device.get("vid").and_then(|v| v.as_str())?;
    let pid = device.get("pid").and_then(|p| p.as_str())?;
    Some(format!("{}:{}", vid, pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compare_usb_connected() {
        let before = json!([{
            "connected_devices": [
                {"vid": "1234", "pid": "5678"}
            ]
        }]);
        
        let after = json!([{
            "connected_devices": [
                {"vid": "1234", "pid": "5678"},
                {"vid": "abcd", "pid": "ef01"}
            ]
        }]);
        
        let comparison = compare_usb(&before, &after);
        assert_eq!(comparison.added.len(), 1);
        assert_eq!(comparison.removed.len(), 0);
        assert_eq!(comparison.unchanged_count, 1);
    }

    #[test]
    fn test_compare_usb_disconnected() {
        let before = json!([{
            "connected_devices": [
                {"vid": "1234", "pid": "5678"},
                {"vid": "abcd", "pid": "ef01"}
            ]
        }]);
        
        let after = json!([{
            "connected_devices": [
                {"vid": "1234", "pid": "5678"}
            ]
        }]);
        
        let comparison = compare_usb(&before, &after);
        assert_eq!(comparison.removed.len(), 1);
        assert_eq!(comparison.unchanged_count, 1);
    }
}