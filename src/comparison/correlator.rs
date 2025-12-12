use super::{TimelineEvent, Correlation};
use chrono::{DateTime, Duration};
use crate::parsers::ParserType;

/// Correlate timeline events to find suspicious patterns
pub fn correlate_events(events: &[TimelineEvent]) -> Vec<Correlation> {
    let mut correlations = Vec::new();
    
    // Sort events by timestamp
    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    
    // Pattern 1: USB connection followed by package install (within 5 minutes)
    correlations.extend(find_usb_then_install(&sorted_events));
    
    // Pattern 2: Package install followed by reboot (within 2 minutes)
    correlations.extend(find_install_then_reboot(&sorted_events));
    
    // Pattern 3: Multiple reboots in short time (suspicious)
    correlations.extend(find_multiple_reboots(&sorted_events));
    
    // Pattern 4: Suspicious process after USB connection
    correlations.extend(find_usb_then_process(&sorted_events));
    
    correlations
}

/// Find USB connection followed by package installation
fn find_usb_then_install(events: &[TimelineEvent]) -> Vec<Correlation> {
    let mut correlations = Vec::new();
    
    for (i, usb_event) in events.iter().enumerate() {
        if usb_event.parser != ParserType::Usb || usb_event.change_type != "added" {
            continue;
        }
        
        // Look for package installs within 5 minutes
        for pkg_event in events.iter().skip(i + 1) {
            if pkg_event.parser != ParserType::Package || pkg_event.change_type != "added" {
                continue;
            }
            
            if let Some(duration) = time_diff(&usb_event.timestamp, &pkg_event.timestamp) {
                if duration > Duration::zero() && duration < Duration::minutes(5) {
                    correlations.push(Correlation {
                        events: vec![usb_event.clone(), pkg_event.clone()],
                        correlation_type: "usb_then_install".to_string(),
                        description: format!(
                            "Package installed {} after USB device connected (possible sideloading)",
                            format_duration(duration)
                        ),
                    });
                }
            }
        }
    }
    
    correlations
}

/// Find package install followed by reboot
fn find_install_then_reboot(events: &[TimelineEvent]) -> Vec<Correlation> {
    let mut correlations = Vec::new();
    
    for (i, pkg_event) in events.iter().enumerate() {
        if pkg_event.parser != ParserType::Package || pkg_event.change_type != "added" {
            continue;
        }
        
        // Look for reboots within 2 minutes
        for power_event in events.iter().skip(i + 1) {
            if power_event.parser != ParserType::Power {
                continue;
            }
            
            let event_type = power_event.details.get("power_event_type")
                .and_then(|e| e.as_str())
                .unwrap_or("");
            
            if event_type != "REBOOT" && event_type != "SHUTDOWN" {
                continue;
            }
            
            if let Some(duration) = time_diff(&pkg_event.timestamp, &power_event.timestamp) {
                if duration > Duration::zero() && duration < Duration::minutes(2) {
                    correlations.push(Correlation {
                        events: vec![pkg_event.clone(), power_event.clone()],
                        correlation_type: "install_then_reboot".to_string(),
                        description: format!(
                            "Device rebooted {} after package installation (typical malware activation pattern)",
                            format_duration(duration)
                        ),
                    });
                }
            }
        }
    }
    
    correlations
}

/// Find multiple reboots in a short time period
fn find_multiple_reboots(events: &[TimelineEvent]) -> Vec<Correlation> {
    let mut correlations = Vec::new();
    
    let reboots: Vec<&TimelineEvent> = events.iter()
        .filter(|e| {
            e.parser == ParserType::Power &&
            e.details.get("power_event_type")
                .and_then(|t| t.as_str())
                .map(|t| t == "REBOOT")
                .unwrap_or(false)
        })
        .collect();
    
    // Look for 3+ reboots within 10 minutes
    for i in 0..reboots.len().saturating_sub(2) {
        if let Some(duration) = time_diff(&reboots[i].timestamp, &reboots[i + 2].timestamp) {
            if duration < Duration::minutes(10) {
                let reboot_events = reboots[i..=i + 2].iter().map(|&e| e.clone()).collect();
                correlations.push(Correlation {
                    events: reboot_events,
                    correlation_type: "multiple_reboots".to_string(),
                    description: format!(
                        "Multiple reboots detected within {} (unusual behavior)",
                        format_duration(duration)
                    ),
                });
                break; // Only report once
            }
        }
    }
    
    correlations
}

/// Find USB connection followed by suspicious process
fn find_usb_then_process(events: &[TimelineEvent]) -> Vec<Correlation> {
    let mut correlations = Vec::new();
    
    for (i, usb_event) in events.iter().enumerate() {
        if usb_event.parser != ParserType::Usb || usb_event.change_type != "added" {
            continue;
        }
        
        // Look for new processes within 5 minutes
        for proc_event in events.iter().skip(i + 1) {
            if proc_event.parser != ParserType::Process || proc_event.change_type != "added" {
                continue;
            }
            
            if let Some(duration) = time_diff(&usb_event.timestamp, &proc_event.timestamp) {
                if duration > Duration::zero() && duration < Duration::minutes(5) {
                    correlations.push(Correlation {
                        events: vec![usb_event.clone(), proc_event.clone()],
                        correlation_type: "usb_then_process".to_string(),
                        description: format!(
                            "New process started {} after USB connection",
                            format_duration(duration)
                        ),
                    });
                }
            }
        }
    }
    
    correlations
}

/// Calculate time difference between two timestamp strings
fn time_diff(before: &str, after: &str) -> Option<Duration> {
    let before_dt = parse_timestamp(before)?;
    let after_dt = parse_timestamp(after)?;
    Some(after_dt.signed_duration_since(before_dt))
}

/// Parse timestamp string (handles multiple formats)
fn parse_timestamp(timestamp: &str) -> Option<DateTime<chrono::Utc>> {
    // Try RFC3339 format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    
    // Try common Android log format: "2025-03-28 10:30:45.123"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.3f") {
        return Some(DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    
    // Try without milliseconds: "2025-03-28 10:30:45"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    
    None
}

/// Format duration in human-readable format
fn format_duration(duration: Duration) -> String {
    let seconds = duration.num_seconds();
    
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_find_usb_then_install() {
        let events = vec![
            TimelineEvent {
                timestamp: "2025-03-28 10:00:00".to_string(),
                parser: ParserType::Usb,
                event_type: "usb_connected".to_string(),
                change_type: "added".to_string(),
                details: json!({"vid": "1234"}),
            },
            TimelineEvent {
                timestamp: "2025-03-28 10:02:00".to_string(),
                parser: ParserType::Package,
                event_type: "package_installed".to_string(),
                change_type: "added".to_string(),
                details: json!({"pkg": "com.evil.app"}),
            },
        ];
        
        let correlations = find_usb_then_install(&events);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].correlation_type, "usb_then_install");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::seconds(30)), "30s");
        assert_eq!(format_duration(Duration::seconds(90)), "1m 30s");
        assert_eq!(format_duration(Duration::seconds(3665)), "1h 1m");
    }
}