use super::Parser;

use serde_json::{json, Value};
use std::error::Error;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const BATTERYSTATS_START_MARKER: &str = "CHECKIN BATTERYSTATS";
const BATTERYSTATS_END_MARKER: &str = "was the duration of 'CHECKIN BATTERYSTATS'";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryStats {
    pub apps: Vec<AppBatteryStats>,
    pub suspicious_apps: Vec<SuspiciousApp>,
    pub total_suspicious: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBatteryStats {
    pub uid: u32,
    pub package_name: String,
    pub network_tx_mobile: u64,
    pub network_rx_mobile: u64,
    pub network_tx_wifi: u64,
    pub network_rx_wifi: u64,
    pub total_network_bytes: u64,
    pub wakelocks: Vec<Wakelock>,
    pub total_wakelock_time_ms: u64,
    pub foreground_service_time_ms: u64,
    pub cpu_user_time_ms: u32,
    pub cpu_system_time_ms: u32,
    pub background_jobs: Vec<BackgroundJob>,
    pub total_job_count: usize,
    pub total_job_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wakelock {
    pub name: String,
    pub wakelock_type: String, // "f" for full, "p" for partial
    pub time_ms: u64,
    pub count: u32,
    pub current_duration_ms: u64,
    pub max_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundJob {
    pub name: String,
    pub time_ms: u64,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousApp {
    pub uid: u32,
    pub package_name: String,
    pub reasons: Vec<String>,
    pub severity: SeverityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct BatteryParser;

impl Default for BatteryParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Battery Parser")
    }
}

impl BatteryParser {
    /// Creates a new HeaderParser
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(BatteryParser {})
    }
}

impl BatteryParser {
    /// Parse batterystats section from the bugreport
    fn parse_battery_section(content: &str) -> Vec<AppBatteryStats> {
        let mut apps: HashMap<u32, AppBatteryStats> = HashMap::new();

        for line in content.lines() {
            if line.starts_with("9,") {
                Self::parse_battery_line(line, &mut apps);
            }
        }

        apps.into_values().collect()
    }

    /// Parse individual battery stats line
    fn parse_battery_line(line: &str, apps: &mut HashMap<u32, AppBatteryStats>) {
        let parts: Vec<&str> = line.split(',').collect();
        
        if parts.len() < 3 {
            return;
        }

        // Parse UID (format: 9,<uid>,l,...)
        let uid = match parts[1].parse::<u32>() {
            Ok(u) => u,
            Err(_) => return,
        };

        // Only process app UIDs (1010000+)
        if uid < 1010000 {
            return;
        }

        let entry = apps.entry(uid).or_insert_with(|| AppBatteryStats {
            uid,
            package_name: String::new(),
            network_tx_mobile: 0,
            network_rx_mobile: 0,
            network_tx_wifi: 0,
            network_rx_wifi: 0,
            total_network_bytes: 0,
            wakelocks: Vec::new(),
            total_wakelock_time_ms: 0,
            foreground_service_time_ms: 0,
            cpu_user_time_ms: 0,
            cpu_system_time_ms: 0,
            background_jobs: Vec::new(),
            total_job_count: 0,
            total_job_time_ms: 0,
        });

        if parts.len() < 4 {
            return;
        }

        // Parse based on record type
        match parts[3] {
            "nt" => Self::parse_network_stats(parts, entry),
            "wl" => Self::parse_wakelock(parts, entry),
            "fgs" => Self::parse_foreground_service(parts, entry),
            "cpu" => Self::parse_cpu_stats(parts, entry),
            "jb" => Self::parse_job_stats(parts, entry),
            "pr" => Self::parse_process_name(parts, entry),
            "awl" => Self::parse_aggregate_wakelock(parts, entry),
            _ => {}
        }
    }

    /// Parse network statistics (nt)
    fn parse_network_stats(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 12 {
            // Format: 9,uid,l,nt,mobile_rx,mobile_tx,wifi_rx,wifi_tx,...
            if let (Ok(mobile_rx), Ok(mobile_tx), Ok(wifi_rx), Ok(wifi_tx)) = (
                parts[4].parse::<u64>(),
                parts[5].parse::<u64>(),
                parts[6].parse::<u64>(),
                parts[7].parse::<u64>(),
            ) {
                entry.network_rx_mobile = mobile_rx;
                entry.network_tx_mobile = mobile_tx;
                entry.network_rx_wifi = wifi_rx;
                entry.network_tx_wifi = wifi_tx;
                entry.total_network_bytes = mobile_rx + mobile_tx + wifi_rx + wifi_tx;
            }
        }
    }

    /// Parse wakelock information (wl)
    fn parse_wakelock(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 14 {
            // Format: 9,uid,l,wl,name,0,type,0,0,0,0,time,p/f,count,0,current,max,max,...
            let name = parts[4].to_string();
            let wakelock_type = parts[6].to_string();
            
            // Parse wakelock time based on type
            let time_idx = if parts[12] == "p" { 11 } else { 11 };
            let count_idx = if parts[12] == "p" { 13 } else { 13 };
            
            // Get values with safe parsing
            if let (Some(time_str), Some(count_str)) = (parts.get(time_idx), parts.get(count_idx)) {
                if let (Ok(time), Ok(count)) = (time_str.parse::<u64>(), count_str.parse::<u32>()) {
                    let current = parts.get(14).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                    let max = parts.get(15).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);

                    entry.wakelocks.push(Wakelock {
                        name,
                        wakelock_type,
                        time_ms: time,
                        count,
                        current_duration_ms: current,
                        max_duration_ms: max,
                    });
                    entry.total_wakelock_time_ms += time;
                }
            }
        }
    }

    /// Parse aggregate wakelock time (awl)
    fn parse_aggregate_wakelock(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 5 {
            if let Ok(total_time) = parts[4].parse::<u64>() {
                entry.total_wakelock_time_ms = total_time;
            }
        }
    }

    /// Parse foreground service time (fgs)
    fn parse_foreground_service(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 5 {
            if let Ok(fgs_time) = parts[4].parse::<u64>() {
                entry.foreground_service_time_ms = fgs_time;
            }
        }
    }

    /// Parse CPU statistics (cpu)
    fn parse_cpu_stats(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 6 {
            if let (Ok(user_time), Ok(system_time)) = (
                parts[4].parse::<u32>(),
                parts[5].parse::<u32>(),
            ) {
                entry.cpu_user_time_ms = user_time;
                entry.cpu_system_time_ms = system_time;
            }
        }
    }

    /// Parse background job statistics (jb)
    fn parse_job_stats(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 6 {
            let job_name = parts[4].to_string();
            if let (Ok(time), Ok(count)) = (
                parts[5].parse::<u64>(),
                parts[6].parse::<u32>(),
            ) {
                entry.background_jobs.push(BackgroundJob {
                    name: job_name,
                    time_ms: time,
                    count,
                });
                entry.total_job_time_ms += time;
                entry.total_job_count += count as usize;
            }
        }
    }

    /// Parse process name (pr)
    fn parse_process_name(parts: Vec<&str>, entry: &mut AppBatteryStats) {
        if parts.len() >= 5 && entry.package_name.is_empty() {
            entry.package_name = parts[4].to_string();
        }
    }

    /// Detect suspicious battery usage patterns
    fn detect_suspicious_usage(apps: &[AppBatteryStats]) -> Vec<SuspiciousApp> {
        apps.par_iter()
            .filter_map(|app| {
                let mut reasons = Vec::new();
                let mut severity_score = 0;

                // Check for excessive wakelock usage (> 30 seconds)
                if app.total_wakelock_time_ms > 30_000 {
                    reasons.push(format!(
                        "Excessive wakelock usage: {}ms ({:.2}s)",
                        app.total_wakelock_time_ms,
                        app.total_wakelock_time_ms as f64 / 1000.0
                    ));
                    severity_score += 2;

                    // Critical if > 10 minutes
                    if app.total_wakelock_time_ms > 600_000 {
                        severity_score += 3;
                    }
                }

                // Check for high network traffic (> 100 MB)
                let mb_transferred = app.total_network_bytes as f64 / (1024.0 * 1024.0);
                if app.total_network_bytes > 100_000_000 {
                    reasons.push(format!(
                        "High network usage: {:.2} MB",
                        mb_transferred
                    ));
                    severity_score += 2;

                    // Critical if > 500 MB
                    if app.total_network_bytes > 500_000_000 {
                        severity_score += 3;
                    }
                }

                // Check for long-running foreground service (> 12 hours)
                let hours = app.foreground_service_time_ms as f64 / (1000.0 * 60.0 * 60.0);
                if app.foreground_service_time_ms > 43_200_000 {
                    reasons.push(format!(
                        "Long-running foreground service: {:.2} hours",
                        hours
                    ));
                    severity_score += 2;
                }

                // Check for frequent background jobs (> 10 jobs)
                if app.total_job_count > 10 {
                    reasons.push(format!(
                        "Frequent background jobs: {} jobs with total time {}ms",
                        app.total_job_count,
                        app.total_job_time_ms
                    ));
                    severity_score += 1;

                    // Higher severity for > 20 jobs
                    if app.total_job_count > 20 {
                        severity_score += 2;
                    }
                }

                // Check for high CPU time ratio (system time > user time)
                if app.cpu_system_time_ms > app.cpu_user_time_ms 
                    && app.cpu_system_time_ms > 10_000 {
                    reasons.push(format!(
                        "High system CPU time: {}ms system vs {}ms user",
                        app.cpu_system_time_ms,
                        app.cpu_user_time_ms
                    ));
                    severity_score += 1;
                }

                // Check for suspicious wakelock patterns
                for wakelock in &app.wakelocks {
                    // Very long individual wakelocks
                    if wakelock.time_ms > 60_000 {
                        reasons.push(format!(
                            "Long wakelock '{}': {}ms",
                            wakelock.name,
                            wakelock.time_ms
                        ));
                        severity_score += 1;
                    }

                    // Frequent wakelock acquisitions
                    if wakelock.count > 100 {
                        reasons.push(format!(
                            "Frequent wakelock '{}': {} acquisitions",
                            wakelock.name,
                            wakelock.count
                        ));
                        severity_score += 1;
                    }
                }

                if !reasons.is_empty() {
                    let severity = match severity_score {
                        0..=2 => SeverityLevel::Low,
                        3..=5 => SeverityLevel::Medium,
                        6..=9 => SeverityLevel::High,
                        _ => SeverityLevel::Critical,
                    };

                    Some(SuspiciousApp {
                        uid: app.uid,
                        package_name: app.package_name.clone(),
                        reasons,
                        severity,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract the batterystats section from the bugreport
    fn extract_battery_section(data: &[u8]) -> Option<String> {
        let content = String::from_utf8_lossy(data);
        
        let start = content.find(BATTERYSTATS_START_MARKER)?;
        let end = content[start..].find(BATTERYSTATS_END_MARKER)? + start;
        
        Some(content[start..end].to_string())
    }
}

impl Parser for BatteryParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // Extract battery section
        let battery_section = Self::extract_battery_section(data)
            .ok_or("Could not find CHECKIN BATTERYSTATS section")?;

        // Parse all apps
        let apps = Self::parse_battery_section(&battery_section);

        // Detect suspicious usage
        let suspicious_apps = Self::detect_suspicious_usage(&apps);
        let total_suspicious = suspicious_apps.len();

        // Sort suspicious apps by severity
        let mut suspicious_apps = suspicious_apps;
        suspicious_apps.sort_by(|a, b| b.severity.cmp(&a.severity));

        let stats = BatteryStats {
            apps,
            suspicious_apps,
            total_suspicious,
        };

        Ok(json!(stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wakelock() {
        let mut apps = HashMap::new();
        let line = "9,1010350,l,wl,*alarm*,0,f,0,0,0,0,221,p,28,0,42,400,0";
        BatteryParser::parse_battery_line(line, &mut apps);
        
        assert_eq!(apps.len(), 1);
        let app = apps.get(&1010350).unwrap();
        assert_eq!(app.wakelocks.len(), 1);
        assert_eq!(app.wakelocks[0].name, "*alarm*");
    }

    #[test]
    fn test_parse_network_stats() {
        let mut apps = HashMap::new();
        let line = "9,1010350,l,nt,183689,94337,623032,744394,616,622,2140,2469,163434007,20,0,0,8,48";
        BatteryParser::parse_battery_line(line, &mut apps);
        
        assert_eq!(apps.len(), 1);
        let app = apps.get(&1010350).unwrap();
        assert_eq!(app.network_rx_mobile, 183689);
        assert_eq!(app.network_tx_mobile, 94337);
    }

    #[test]
    fn test_suspicious_detection_wakelock() {
        let app = AppBatteryStats {
            uid: 1010350,
            package_name: "com.example.app".to_string(),
            network_tx_mobile: 0,
            network_rx_mobile: 0,
            network_tx_wifi: 0,
            network_rx_wifi: 0,
            total_network_bytes: 0,
            wakelocks: Vec::new(),
            total_wakelock_time_ms: 36_531, // Over 30 seconds
            foreground_service_time_ms: 0,
            cpu_user_time_ms: 0,
            cpu_system_time_ms: 0,
            background_jobs: Vec::new(),
            total_job_count: 0,
            total_job_time_ms: 0,
        };

        let suspicious = BatteryParser::detect_suspicious_usage(&[app]);
        assert_eq!(suspicious.len(), 1);
        assert!(suspicious[0].reasons[0].contains("wakelock"));
    }

    #[test]
    fn test_suspicious_detection_network() {
        let app = AppBatteryStats {
            uid: 1010351,
            package_name: "com.example.network".to_string(),
            network_tx_mobile: 50_000_000,
            network_rx_mobile: 60_000_000,
            network_tx_wifi: 0,
            network_rx_wifi: 0,
            total_network_bytes: 110_000_000, // Over 100 MB
            wakelocks: Vec::new(),
            total_wakelock_time_ms: 0,
            foreground_service_time_ms: 0,
            cpu_user_time_ms: 0,
            cpu_system_time_ms: 0,
            background_jobs: Vec::new(),
            total_job_count: 0,
            total_job_time_ms: 0,
        };

        let suspicious = BatteryParser::detect_suspicious_usage(&[app]);
        assert_eq!(suspicious.len(), 1);
        assert!(suspicious[0].reasons[0].contains("network"));
    }
}