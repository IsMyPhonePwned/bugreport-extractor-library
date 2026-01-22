use super::{ComparisonResult, ParserComparison, Correlation};
use serde_json::Value;
use crate::parsers::ParserType;

/// Output comparison results in the specified format
pub fn output_comparison(result: &ComparisonResult, format: &str) {
    match format {
        "json" => output_json(result),
        "text" => output_text(result),
        _ => output_text(result),
    }
}

/// Output comparison in JSON format
fn output_json(result: &ComparisonResult) {
    if let Ok(json) = serde_json::to_string_pretty(result) {
        println!("{}", json);
    }
}

/// Output comparison in human-readable text format
fn output_text(result: &ComparisonResult) {
    println!("\n{}", "=".repeat(60));
    println!("📊 COMPARISON REPORT");
    println!("{}", "=".repeat(60));
    println!("Before: {}", result.before_file);
    println!("After:  {}", result.after_file);
    println!();
    
    if !result.has_changes() {
        println!("✓ No changes detected");
        return;
    }
    
    println!("Total changes: {}", result.total_changes());
    println!();
    
    // Output changes by parser
    for parser_type in &[
        ParserType::Package,
        ParserType::Usb,
        ParserType::Process,
        ParserType::Power,
        ParserType::Battery,
    ] {
        if let Some(comparison) = result.parser_comparisons.get(parser_type) {
            if comparison.has_changes() {
                output_parser_comparison(comparison);
            }
        }
    }
    
    // Output timeline if there are events
    if !result.timeline_events.is_empty() {
        output_timeline(&result.timeline_events);
    }
    
    // Output correlations if found
    if !result.correlations.is_empty() {
        output_correlations(&result.correlations);
    }
    
    println!("{}", "=".repeat(60));
}

/// Output changes for a single parser
fn output_parser_comparison(comparison: &ParserComparison) {
    let icon = match comparison.parser_type {
        ParserType::Package => "📦",
        ParserType::Process => "⚙️ ",
        ParserType::Power => "⚡",
        ParserType::Usb => "🔌",
        ParserType::Battery => "🔋",
        ParserType::Network => "🌐",
        ParserType::Bluetooth => "📱",
        _ => "📊",
    };
    
    println!("{} {}", icon, format_parser_name(&comparison.parser_type).to_uppercase());
    println!("{}", "-".repeat(60));
    
    // Added items
    if !comparison.added.is_empty() {
        println!("  ➕ Added ({}):", comparison.added.len());
        for item in &comparison.added {
            println!("    - {}", format_item(&comparison.parser_type, item));
        }
        println!();
    }
    
    // Removed items
    if !comparison.removed.is_empty() {
        println!("  ➖ Removed ({}):", comparison.removed.len());
        for item in &comparison.removed {
            println!("    - {}", format_item(&comparison.parser_type, item));
        }
        println!();
    }
    
    // Modified items
    if !comparison.modified.is_empty() {
        println!("  🔄 Modified ({}):", comparison.modified.len());
        for (before, after) in &comparison.modified {
            println!("    - {}", format_modification(&comparison.parser_type, before, after));
        }
        println!();
    }
    
    // Unchanged count
    if comparison.unchanged_count > 0 {
        println!("  ✓ Unchanged: {}", comparison.unchanged_count);
        println!();
    }
}

/// Output timeline of events
fn output_timeline(events: &[TimelineEvent]) {
    println!("📅 TIMELINE");
    println!("{}", "-".repeat(60));
    
    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    
    for event in sorted_events.iter().take(20) {
        let icon = match event.change_type.as_str() {
            "added" => "➕",
            "removed" => "➖",
            "modified" => "🔄",
            _ => "•",
        };
        
        println!("  {} {} - {} ({})",
            icon,
            event.timestamp,
            event.event_type,
            format_parser_name(&event.parser)
        );
    }
    
    if sorted_events.len() > 20 {
        println!("  ... and {} more events", sorted_events.len() - 20);
    }
    
    println!();
}

/// Output correlations
fn output_correlations(correlations: &[Correlation]) {
    println!("⚠️  CORRELATED ACTIVITY");
    println!("{}", "-".repeat(60));
    
    for (i, correlation) in correlations.iter().enumerate() {
        println!("  {}. {}", i + 1, correlation.description);
        println!("     Events:");
        for event in &correlation.events {
            println!("       • {} - {} ({})",
                event.timestamp,
                event.event_type,
                format_parser_name(&event.parser)
            );
        }
        println!();
    }
}

/// Format parser name for display
fn format_parser_name(parser_type: &ParserType) -> &str {
    match parser_type {
        ParserType::Package => "Package",
        ParserType::Process => "Process",
        ParserType::Power => "Power",
        ParserType::Usb => "USB",
        ParserType::Battery => "Battery",
        ParserType::Header => "Header",
        ParserType::Memory => "Memory",
        ParserType::Crash => "Crash",
        ParserType::Network => "Network",
        ParserType::Bluetooth => "Bluetooth",
        ParserType::DevicePolicy => "Device Policy",
        ParserType::Adb => "ADB",
        ParserType::Authentication => "Authentication",
    }
}

/// Format an item for display based on parser type
fn format_item(parser_type: &ParserType, item: &Value) -> String {
    match parser_type {
        ParserType::Package => {
            let pkg = item.get("pkg").and_then(|p| p.as_str()).unwrap_or("unknown");
            let version = item.get("versionCode").and_then(|v| v.as_u64());
            if let Some(v) = version {
                format!("{} (version: {})", pkg, v)
            } else {
                pkg.to_string()
            }
        }
        ParserType::Process => {
            let cmd = item.get("cmd").and_then(|c| c.as_str()).unwrap_or("unknown");
            let pid = item.get("pid").and_then(|p| p.as_u64());
            if let Some(p) = pid {
                format!("{} (PID: {})", cmd, p)
            } else {
                cmd.to_string()
            }
        }
        ParserType::Usb => {
            let vid = item.get("vid").and_then(|v| v.as_str()).unwrap_or("unknown");
            let pid = item.get("pid").and_then(|p| p.as_str()).unwrap_or("unknown");
            let product = item.get("product").and_then(|p| p.as_str());
            if let Some(p) = product {
                format!("{}:{} ({})", vid, pid, p)
            } else {
                format!("{}:{}", vid, pid)
            }
        }
        ParserType::Network => {
            // Format network items (could be socket, interface, or network stats)
            if let Some(local_addr) = item.get("local_address").and_then(|a| a.as_str()) {
                format!("{}", local_addr)
            } else if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                format!("{}", name)
            } else {
                format!("{:?}", item)
            }
        },
        ParserType::Bluetooth => {
            // Format Bluetooth devices
            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                if let Some(mac) = item.get("mac_address").and_then(|m| m.as_str()) {
                    format!("{} ({})", name, mac)
                } else if let Some(masked) = item.get("masked_address").and_then(|m| m.as_str()) {
                    format!("{} ({})", name, masked)
                } else {
                    format!("{}", name)
                }
            } else if let Some(mac) = item.get("mac_address").and_then(|m| m.as_str()) {
                format!("{}", mac)
            } else {
                format!("{:?}", item)
            }
        }
        ParserType::Power => {
            let event_type = item.get("power_event_type")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown");
            let reason = item.get("reason").and_then(|r| r.as_str());
            if let Some(r) = reason {
                format!("{} (reason: {})", event_type, r)
            } else {
                event_type.to_string()
            }
        }
        ParserType::DevicePolicy => {
            // Format device policy items (could be device admin, profile owner, etc.)
            if let Some(package) = item.get("package").and_then(|p| p.as_str()) {
                if let Some(receiver) = item.get("receiver").and_then(|r| r.as_str()) {
                    format!("{} ({})", package, receiver)
                } else {
                    package.to_string()
                }
            } else if let Some(component) = item.get("component").and_then(|c| c.as_str()) {
                component.to_string()
            } else {
                format!("{:?}", item)
            }
        }
        ParserType::Adb => {
            // Format ADB items (connection info, keys, etc.)
            if let Some(connected) = item.get("connected_to_adb").and_then(|c| c.as_bool()) {
                if connected {
                    if let Some(last_key) = item.get("last_key_received").and_then(|k| k.as_str()) {
                        format!("Connected (last key: {})", &last_key[..16])
                    } else {
                        "Connected".to_string()
                    }
                } else {
                    "Not connected".to_string()
                }
            } else if let Some(identifier) = item.get("identifier").and_then(|i| i.as_str()) {
                format!("Key: {}", identifier)
            } else {
                format!("{:?}", item)
            }
        }
        ParserType::Authentication => {
            // Format authentication events
            let timestamp = item.get("timestamp").and_then(|t| t.as_str()).unwrap_or("unknown");
            let user_id = item.get("user_id").and_then(|u| u.as_u64());
            let success = item.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
            let auth_type = item.get("auth_type").and_then(|a| a.as_str());
            
            let status = if success { "Success" } else { "Failed" };
            let user_str = if let Some(uid) = user_id {
                format!("user {}", uid)
            } else {
                "unknown user".to_string()
            };
            
            if let Some(auth) = auth_type {
                format!("{} {} {} ({})", timestamp, status, user_str, auth)
            } else {
                format!("{} {} {}", timestamp, status, user_str)
            }
        }
        _ => {
            // Generic formatting
            serde_json::to_string(item).unwrap_or_else(|_| "unknown".to_string())
        }
    }
}

/// Format a modification for display
fn format_modification(parser_type: &ParserType, before: &Value, after: &Value) -> String {
    match parser_type {
        ParserType::Package => {
            let pkg = after.get("pkg").and_then(|p| p.as_str()).unwrap_or("unknown");
            let before_version = before.get("versionCode").and_then(|v| v.as_u64());
            let after_version = after.get("versionCode").and_then(|v| v.as_u64());
            
            if let (Some(bv), Some(av)) = (before_version, after_version) {
                format!("{}: {} → {}", pkg, bv, av)
            } else {
                format!("{}: modified", pkg)
            }
        }
        _ => {
            format!("{} → {}", format_item(parser_type, before), format_item(parser_type, after))
        }
    }
}

use super::TimelineEvent;