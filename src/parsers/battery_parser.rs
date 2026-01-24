use super::Parser;

use serde_json::{json, Value};
use std::error::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;

const BATTERYSTATS_START_MARKER: &str = "CHECKIN BATTERYSTATS";
const BATTERYSTATS_END_MARKER: &str = "was the duration of 'CHECKIN BATTERYSTATS'";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryStats {
    pub apps: Vec<AppBatteryStats>,
    pub suspicious_apps: Vec<SuspiciousApp>,
    pub total_suspicious: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_info: Option<BatteryHardwareInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub battery_history: Vec<BatteryHistoryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryHardwareInfo {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kernel_log_entries: Vec<KernelBatteryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelBatteryInfo {
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_mv: Option<i32>,  // Main battery voltage (mV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vavgm_mv: Option<i32>,  // Average main battery voltage (mV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vs_mv: Option<i32>,  // Sub battery voltage (mV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vavgs_mv: Option<i32>,  // Average sub battery voltage (mV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chgin_s_mv: Option<i32>,  // Charger input voltage (mV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inow_ma: Option<i32>,  // Current now (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iavg_ma: Option<i32>,  // Average current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isysavg_ma: Option<i32>,  // System average current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inow_m_ma: Option<i32>,  // Main battery current now (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iavg_m_ma: Option<i32>,  // Main battery average current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inow_s_ma: Option<i32>,  // Sub battery current now (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iavg_s_ma: Option<i32>,  // Sub battery average current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imax_ma: Option<i32>,  // Max current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ichg_ma: Option<i32>,  // Charging current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ichg_m_ma: Option<i32>,  // Main battery charging current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ichg_s_ma: Option<i32>,  // Sub battery charging current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soc_percent: Option<f32>,  // State of charge (%)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msoc_percent: Option<f32>,  // Measured state of charge (%)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssoc_percent: Option<f32>,  // Sub battery state of charge (%)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsub: Option<i32>,  // Sub temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tbat: Option<i32>,  // Battery temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tusb: Option<i32>,  // USB temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tchg: Option<i32>,  // Charger temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub twpc: Option<i32>,  // Wireless charging temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tblkt: Option<i32>,  // Block temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlrp: Option<i32>,  // LRP temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdchg: Option<i32>,  // Discharge temperature
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryHistoryEntry {
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,  // charging, discharging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,  // good, unknown, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plug: Option<String>,  // ac, usb, wireless, none
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temp: Option<i32>,  // Temperature (0.1°C units, so 234 = 23.4°C)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volt: Option<i32>,  // Voltage (mV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<i32>,  // Current (mA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge: Option<i32>,  // Charge level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ap_temp: Option<i32>,  // AP temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pa_temp: Option<i32>,  // PA temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skin_temp: Option<i32>,  // Skin temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_batt_temp: Option<i32>,  // Sub battery temperature
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,  // +plugged, -plugged, +charging, etc.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub sdk_version: u32,
    pub build_number_1: String,
    pub build_number_2: String,
    pub build_number_3: String,
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
    /// Creates a new BatteryParser
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(BatteryParser {})
    }
    
    /// Get compiled regex for extracting key=value pairs from battery history lines
    /// Pattern matches: key=value where value can be unquoted or quoted
    fn get_kv_regex() -> Regex {
        // Matches: key=value or key="quoted value"
        // Value can be:
        //   - Unquoted: any characters except space until next space or end of line
        //   - Quoted: "..." (can contain spaces and special chars)
        // Examples: status=discharging, temp=234, state=1000:"sensor:0x73677276"
        // Pattern: (\w+)= captures the key, then either [^\s]+ (unquoted) or "[^"]*" (quoted)
        Regex::new(r#"(\w+)=([^\s"]+|"[^"]*")"#).unwrap()
    }
    /// Parse batterystats section from the bugreport
    /// Returns apps and version info
    fn parse_battery_section(content: &str) -> (Vec<AppBatteryStats>, Option<VersionInfo>) {
        let mut apps: HashMap<u32, AppBatteryStats> = HashMap::new();
        let mut version_info = None;

        for line in content.lines() {
            if line.starts_with("9,") {
                // Skip HSP records (they don't bring value)
                if line.starts_with("9,hsp,") {
                    continue;
                }
                
                // Check for version info (format: 9,<uid>,i,vers,...)
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 4 && parts[2] == "i" && parts[3] == "vers" {
                    if let Some(version) = Self::parse_version_info(line) {
                        version_info = Some(version);
                    }
                    continue;
                }
                
                // Parse regular app battery stats
                Self::parse_battery_line(line, &mut apps);
            }
        }

        (apps.into_values().collect(), version_info)
    }
    
    /// Parse version info entry
    /// Format: 9,<uid>,i,vers,<sdk_version>,<build_number_1>,<build_number_2>,<build_number_3>
    /// Example: 9,0,i,vers,36,1048791,BP2A.250605.031.A3,BP2A.250605.031.A3
    fn parse_version_info(line: &str) -> Option<VersionInfo> {
        let parts: Vec<&str> = line.split(',').collect();
        
        if parts.len() < 8 {
            return None;
        }
        
        // parts[0] = "9"
        // parts[1] = uid (usually 0)
        // parts[2] = "i"
        // parts[3] = "vers"
        // parts[4] = sdk_version
        // parts[5] = build_number_1
        // parts[6] = build_number_2
        // parts[7] = build_number_3
        
        let sdk_version = parts[4].parse::<u32>().ok()?;
        
        Some(VersionInfo {
            sdk_version,
            build_number_1: parts[5].to_string(),
            build_number_2: parts[6].to_string(),
            build_number_3: parts[7].to_string(),
        })
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

    /// Extract the batterystats section from the bugreport
    fn extract_battery_section(data: &[u8]) -> Option<String> {
        let content = String::from_utf8_lossy(data);
        
        let start = content.find(BATTERYSTATS_START_MARKER)?;
        let end = content[start..].find(BATTERYSTATS_END_MARKER)? + start;
        
        Some(content[start..end].to_string())
    }

    /// Extract KERNEL LOG section
    fn extract_kernel_log_section(data: &[u8]) -> Option<String> {
        let content = String::from_utf8_lossy(data);
        
        let start_delimiter = "------ KERNEL LOG (dmesg) ------";
        let end_marker = " was the duration of 'KERNEL LOG (dmesg)' ------";
        
        let start = content.find(start_delimiter)?;
        let section_start = start + start_delimiter.len();
        let remaining = &content[section_start..];
        
        // Find the end marker - look for the exact end marker string
        let end = remaining
            .find(end_marker)
            .map(|end_pos| section_start + end_pos)
            .unwrap_or(content.len());
        
        // Extract only the content between start and end (excluding the end marker)
        Some(content[section_start..end].to_string())
    }

    /// Extract SEC LOG section
    fn extract_sec_log_section(data: &[u8]) -> Option<String> {
        let content = String::from_utf8_lossy(data);
        
        let start_delimiter = "------ SEC LOG (/proc/sec_log) ------";
        let end_marker = " was the duration of 'SEC LOG (/proc/sec_log)' ------";
        
        let start = content.find(start_delimiter)?;
        let section_start = start + start_delimiter.len();
        let remaining = &content[section_start..];
        
        // Find the end marker - look for the exact end marker string
        let end = remaining
            .find(end_marker)
            .map(|end_pos| section_start + end_pos)
            .unwrap_or(content.len());
        
        // Extract only the content between start and end (excluding the end marker)
        Some(content[section_start..end].to_string())
    }

    /// Parse kernel log battery info entries
    /// Only parses lines within the extracted section content that contain "sec_bat_get_battery_info"
    fn parse_kernel_battery_info(content: &str) -> Vec<KernelBatteryInfo> {
        let mut entries = Vec::new();
        
        // Fast pre-filter: only process lines that contain "sec_bat_get_battery_info"
        const SEARCH_PATTERN: &[u8] = b"sec_bat_get_battery_info";
        
        for line in content.lines() {
            // Stop parsing if we hit the end marker (shouldn't happen if extraction is correct, but safety check)
            if line.contains(" was the duration of 'KERNEL LOG (dmesg)'") {
                break;
            }
            
            // Fast byte-level check for the pattern
            let line_bytes = line.as_bytes();
            if !line_bytes.windows(SEARCH_PATTERN.len()).any(|window| {
                window.eq_ignore_ascii_case(SEARCH_PATTERN)
            }) {
                continue;
            }
            
            // Only parse lines with sec_bat_get_battery_info (double-check with string search)
            if line.contains("sec_bat_get_battery_info:") {
                if let Some(entry) = Self::parse_kernel_battery_line(line) {
                    entries.push(entry);
                }
            }
        }
        
        entries
    }

    /// Parse a single kernel battery info line
    /// Only processes lines that contain "sec_bat_get_battery_info:"
    fn parse_kernel_battery_line(line: &str) -> Option<KernelBatteryInfo> {
        // First verify the line contains sec_bat_get_battery_info
        if !line.contains("sec_bat_get_battery_info:") {
            return None;
        }
        
        // Extract timestamp (format: [timestamp] or <level>[timestamp])
        // Examples: [211662.753469] or <6>[211755.297902]
        let timestamp = if let Some(bracket_start) = line.find('[') {
            if let Some(bracket_end) = line[bracket_start + 1..].find(']') {
                line[bracket_start + 1..bracket_start + 1 + bracket_end].to_string()
            } else {
                return None;
            }
        } else {
            return None;
        };
        
        // Find the sec_bat_get_battery_info: part
        let info_start = line.find("sec_bat_get_battery_info:")?;
        let info_content = &line[info_start + "sec_bat_get_battery_info:".len()..];
        
        // Helper function to extract value from pattern like "Vm(4014mV)"
        let extract_value = |pattern: &str| -> Option<i32> {
            if let Some(start) = info_content.find(pattern) {
                let after_pattern = &info_content[start + pattern.len()..];
                if let Some(open_paren) = after_pattern.find('(') {
                    let after_paren = &after_pattern[open_paren + 1..];
                    if let Some(close_paren) = after_paren.find(')') {
                        let value_str = &after_paren[..close_paren];
                        // Remove unit suffix (mV, mA, %, etc.)
                        let value_str = value_str.trim_end_matches("mV")
                            .trim_end_matches("mA")
                            .trim_end_matches("%")
                            .trim();
                        value_str.parse::<i32>().ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        
        // Helper function to extract percentage value
        let extract_percent = |pattern: &str| -> Option<f32> {
            if let Some(start) = info_content.find(pattern) {
                let after_pattern = &info_content[start + pattern.len()..];
                if let Some(open_paren) = after_pattern.find('(') {
                    let after_paren = &after_pattern[open_paren + 1..];
                    if let Some(close_paren) = after_paren.find('%') {
                        let value_str = &after_paren[..close_paren];
                        value_str.parse::<f32>().ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        
        Some(KernelBatteryInfo {
            timestamp,
            vm_mv: extract_value("Vm"),
            vavgm_mv: extract_value("Vavgm"),
            vs_mv: extract_value("Vs"),
            vavgs_mv: extract_value("Vavgs"),
            chgin_s_mv: extract_value("Chgin_s"),
            inow_ma: extract_value("Inow"),
            iavg_ma: extract_value("Iavg"),
            isysavg_ma: extract_value("Isysavg"),
            inow_m_ma: extract_value("Inow_m"),
            iavg_m_ma: extract_value("Iavg_m"),
            inow_s_ma: extract_value("Inow_s"),
            iavg_s_ma: extract_value("Iavg_s"),
            imax_ma: extract_value("Imax"),
            ichg_ma: extract_value("Ichg"),
            ichg_m_ma: extract_value("Ichg_m"),
            ichg_s_ma: extract_value("Ichg_s"),
            soc_percent: extract_percent("SOC"),
            msoc_percent: extract_percent("MSOC"),
            ssoc_percent: extract_percent("SSOC"),
            tsub: extract_value("Tsub"),
            tbat: extract_value("Tbat"),
            tusb: extract_value("Tusb"),
            tchg: extract_value("Tchg"),
            twpc: extract_value("Twpc"),
            tblkt: extract_value("Tblkt"),
            tlrp: extract_value("Tlrp"),
            tdchg: extract_value("Tdchg"),
        })
    }

    /// Parse battery history entries from SEC LOG
    /// Only parses lines within the extracted section content
    fn parse_battery_history(content: &str) -> Vec<BatteryHistoryEntry> {
        let mut entries = Vec::new();
        
        for line in content.lines() {
            // Stop parsing if we hit the end marker (shouldn't happen if extraction is correct, but safety check)
            if line.contains(" was the duration of 'SEC LOG (/proc/sec_log)'") {
                break;
            }
            
            // Only process lines that contain battery history data (have "status=")
            // This ensures we don't parse random timestamp lines
            // All other validation (timestamp format, valid status, etc.) is done in parse_battery_history_line
            if line.contains("status=") {
                let trimmed = line.trim_start();
                if let Some(entry) = Self::parse_battery_history_line(trimmed) {
                    entries.push(entry);
                }
            }
        }
        
        entries
    }

    /// Parse a single battery history line
    /// Format: "  MM-DD HH:MM:SS.mmm <numbers> <hex> status=... key=value ..."
    fn parse_battery_history_line(line: &str) -> Option<BatteryHistoryEntry> {
        let trimmed = line.trim_start();
        
        // Early validation: must contain "status=" to be a battery history line
        if !trimmed.contains("status=") {
            return None;
        }
        
        // Extract timestamp using regex: "MM-DD HH:MM:SS.mmm"
        let timestamp_re = Regex::new(r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})").unwrap();
        let timestamp = timestamp_re.captures(trimmed)?.get(1)?.as_str().to_string();
        
        // Extract all key=value pairs using regex
        let kv_re = Self::get_kv_regex();
        let mut kv_map: HashMap<String, String> = HashMap::new();
        
        for cap in kv_re.captures_iter(trimmed) {
            let key = cap.get(1)?.as_str().to_string();
            let mut value = cap.get(2)?.as_str().to_string();
            // Remove quotes if present
            if value.starts_with('"') && value.ends_with('"') && value.len() > 1 {
                value = value[1..value.len()-1].to_string();
            }
            kv_map.insert(key, value);
        }
        
        // Helper to extract string value
        let get_str = |key: &str| -> Option<String> {
            kv_map.get(key).cloned()
        };
        
        // Helper to extract integer value
        let get_int = |key: &str| -> Option<i32> {
            kv_map.get(key).and_then(|v| v.parse::<i32>().ok())
        };
        
        // Extract flags (parts starting with + or - followed by word characters, not numbers)
        // Valid flags: +plugged, -plugged, +charging, etc.
        // Invalid: -23, +123 (these are just numbers)
        let flags_re = Regex::new(r"([+-][a-zA-Z_][a-zA-Z0-9_]*)").unwrap();
        let flags: Vec<String> = flags_re
            .find_iter(trimmed)
            .map(|m| m.as_str().to_string())
            .collect();
        
        // Extract all the fields
        let status = get_str("status");
        let health = get_str("health");
        let plug = get_str("plug");
        let temp = get_int("temp");
        let volt = get_int("volt");
        let current = get_int("current");
        let charge = get_int("charge");
        let ap_temp = get_int("ap_temp");
        let pa_temp = get_int("pa_temp");
        let skin_temp = get_int("skin_temp");
        let sub_batt_temp = get_int("sub_batt_temp");
        
        // Validate that this is a valid battery history entry:
        // 1. Must have status field with valid values (charging, discharging, not-charging)
        //    - Trim whitespace and trailing punctuation (commas, periods, etc.)
        // 2. Must have at least one of: volt, temp, or charge (battery-related data)
        let is_valid_status = status.as_ref().map_or(false, |s| {
            let s_clean = s.trim_end_matches(|c: char| c == ',' || c == '.' || c.is_whitespace()).to_lowercase();
            s_clean == "charging" || s_clean == "discharging" || s_clean == "not-charging"
        });
        
        let has_battery_data = volt.is_some() || temp.is_some() || charge.is_some();
        
        // Additional validation: ensure flags are actual flags (not just numbers like "-23")
        // If flags are present, at least one should be valid (start with + or - followed by a letter)
        // Empty flags are fine (some entries don't have flags)
        let has_valid_flags = if flags.is_empty() {
            true  // No flags is fine
        } else {
            // If flags exist, at least one should be valid (not just numbers)
            flags.iter().any(|f| {
                // Valid flags start with + or - followed by a letter (not a number)
                f.len() > 1 && f.chars().nth(1).map_or(false, |c| c.is_alphabetic())
            })
        };
        
        // Only return an entry if it's a valid battery history line
        // Must have: valid status, battery data, and valid flags (if any)
        if is_valid_status && has_battery_data && has_valid_flags {
            Some(BatteryHistoryEntry {
                timestamp,
                status,
                health,
                plug,
                temp,
                volt,
                current,
                charge,
                ap_temp,
                pa_temp,
                skin_temp,
                sub_batt_temp,
                flags,
            })
        } else {
            None
        }
    }
}

impl Parser for BatteryParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // Extract battery section
        let battery_section = Self::extract_battery_section(data)
            .ok_or("Could not find CHECKIN BATTERYSTATS section")?;

        // Parse all apps and version info
        let (apps, version_info) = Self::parse_battery_section(&battery_section);

        // Parse kernel log for hardware battery info
        let mut kernel_entries = Vec::new();
        if let Some(kernel_section) = Self::extract_kernel_log_section(data) {
            kernel_entries = Self::parse_kernel_battery_info(&kernel_section);
        }

        // Parse SEC LOG for battery history
        let mut battery_history = Vec::new();
        if let Some(sec_section) = Self::extract_sec_log_section(data) {
            battery_history = Self::parse_battery_history(&sec_section);
        }

        // Build result
        let mut result = serde_json::Map::new();
        result.insert("apps".to_string(), json!(apps));
        
        if let Some(version) = version_info {
            result.insert("version_info".to_string(), json!(version));
        }
        
        if !kernel_entries.is_empty() {
            let hardware_info = BatteryHardwareInfo {
                kernel_log_entries: kernel_entries,
            };
            result.insert("hardware_info".to_string(), json!(hardware_info));
        }
        
        if !battery_history.is_empty() {
            result.insert("battery_history".to_string(), json!(battery_history));
        }

        Ok(json!(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    fn create_test_battery_section() -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            "------ CHECKIN BATTERYSTATS (/system/bin/dumpsys -T 30000 batterystats -c) ------",
            "9,0,i,vers,36,1048791,BP2A.250605.031.A3,BP2A.250605.031.A3",
            "9,hsp,0,1000,\"sensor:0x22\"",
            "9,hsp,1,1000,\"sensor:0x3e\"",
            "9,1010001,l,pr,com.example.app",
            "9,1010001,l,nt,1000,2000,3000,4000,0,0,0,0",
            "9,1010001,l,cpu,5000,6000",
            "9,1010001,l,wl,TestWakelock,0,f,0,0,0,0,1000,p,5,0,500,1000",
            "9,1010001,l,jb,TestJob,2000,3",
            "9,1010002,l,pr,com.another.app",
            "9,1010002,l,fgs,3000",
            " was the duration of 'CHECKIN BATTERYSTATS' ------"
        )
    }

    fn create_test_kernel_log() -> String {
        format!(
            "{}\n{}\n{}",
            "------ KERNEL LOG (dmesg) ------",
            "[211662.753469] sec_bat_get_battery_info: Vm(4014mV) Vavgm(4000mV) Inow(500mA) SOC(85%) Tbat(234)",
            " was the duration of 'KERNEL LOG (dmesg)' ------"
        )
    }

    fn create_test_sec_log() -> String {
        format!(
            "{}\n{}\n{}\n{}",
            "------ SEC LOG (/proc/sec_log) ------",
            "01-23 10:30:15.123 1234 5678 status=charging volt=4200 temp=234 charge=85 +plugged +charging",
            "01-23 10:30:16.456 1234 5678 status=discharging volt=4190 temp=235 charge=84 -plugged",
            " was the duration of 'SEC LOG (/proc/sec_log)' ------"
        )
    }

    #[test]
    fn test_parse_version_info() {
        let line = "9,0,i,vers,36,1048791,BP2A.250605.031.A3,BP2A.250605.031.A3";
        let version = BatteryParser::parse_version_info(line).unwrap();
        
        assert_eq!(version.sdk_version, 36);
        assert_eq!(version.build_number_1, "1048791");
        assert_eq!(version.build_number_2, "BP2A.250605.031.A3");
        assert_eq!(version.build_number_3, "BP2A.250605.031.A3");
    }

    #[test]
    fn test_parse_version_info_invalid() {
        let line = "9,0,i,vers,36,1048791";
        assert!(BatteryParser::parse_version_info(line).is_none());
    }

    #[test]
    fn test_parse_battery_section_with_version() {
        let content = create_test_battery_section();
        let (apps, version_info) = BatteryParser::parse_battery_section(&content);
        
        assert!(version_info.is_some());
        let version = version_info.unwrap();
        assert_eq!(version.sdk_version, 36);
        
        // Should parse 2 apps
        assert_eq!(apps.len(), 2);
    }

    #[test]
    fn test_parse_app_battery_stats() {
        let content = create_test_battery_section();
        let (apps, _) = BatteryParser::parse_battery_section(&content);
        
        let app1 = apps.iter().find(|a| a.uid == 1010001).unwrap();
        assert_eq!(app1.package_name, "com.example.app");
        assert_eq!(app1.network_rx_mobile, 1000);
        assert_eq!(app1.network_tx_mobile, 2000);
        assert_eq!(app1.network_rx_wifi, 3000);
        assert_eq!(app1.network_tx_wifi, 4000);
        assert_eq!(app1.total_network_bytes, 10000);
        assert_eq!(app1.cpu_user_time_ms, 5000);
        assert_eq!(app1.cpu_system_time_ms, 6000);
        assert_eq!(app1.wakelocks.len(), 1);
        assert_eq!(app1.wakelocks[0].name, "TestWakelock");
        assert_eq!(app1.wakelocks[0].time_ms, 1000);
        assert_eq!(app1.background_jobs.len(), 1);
        assert_eq!(app1.background_jobs[0].name, "TestJob");
        assert_eq!(app1.background_jobs[0].time_ms, 2000);
        
        let app2 = apps.iter().find(|a| a.uid == 1010002).unwrap();
        assert_eq!(app2.package_name, "com.another.app");
        assert_eq!(app2.foreground_service_time_ms, 3000);
    }

    #[test]
    fn test_parse_kernel_battery_info() {
        let content = create_test_kernel_log();
        let entries = BatteryParser::parse_kernel_battery_info(&content);
        
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.timestamp, "211662.753469");
        assert_eq!(entry.vm_mv, Some(4014));
        assert_eq!(entry.vavgm_mv, Some(4000));
        assert_eq!(entry.inow_ma, Some(500));
        assert_eq!(entry.soc_percent, Some(85.0));
        assert_eq!(entry.tbat, Some(234));
    }

    #[test]
    fn test_parse_kernel_battery_info_no_match() {
        let content = "------ KERNEL LOG (dmesg) ------\nSome random log line\n was the duration of 'KERNEL LOG (dmesg)' ------";
        let entries = BatteryParser::parse_kernel_battery_info(&content);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_battery_history() {
        let content = create_test_sec_log();
        let entries = BatteryParser::parse_battery_history(&content);
        
        assert_eq!(entries.len(), 2);
        
        let entry1 = &entries[0];
        assert_eq!(entry1.timestamp, "01-23 10:30:15.123");
        assert_eq!(entry1.status, Some("charging".to_string()));
        assert_eq!(entry1.volt, Some(4200));
        assert_eq!(entry1.temp, Some(234));
        assert_eq!(entry1.charge, Some(85));
        assert!(entry1.flags.contains(&"+plugged".to_string()));
        assert!(entry1.flags.contains(&"+charging".to_string()));
        
        let entry2 = &entries[1];
        assert_eq!(entry2.timestamp, "01-23 10:30:16.456");
        assert_eq!(entry2.status, Some("discharging".to_string()));
        assert_eq!(entry2.volt, Some(4190));
        assert_eq!(entry2.temp, Some(235));
        assert_eq!(entry2.charge, Some(84));
        assert!(entry2.flags.contains(&"-plugged".to_string()));
    }

    #[test]
    fn test_parse_battery_history_invalid_status() {
        let content = "------ SEC LOG (/proc/sec_log) ------\n01-23 10:30:15.123 1234 5678 status=FINISHED, volt=4200\n was the duration of 'SEC LOG (/proc/sec_log)' ------";
        let entries = BatteryParser::parse_battery_history(&content);
        // Should filter out invalid status
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_battery_history_invalid_flags() {
        // The regex only matches flags that start with +/- followed by a letter
        // So "-23" won't be matched, resulting in empty flags which is valid
        // Let's test that entries with only numeric "flags" don't get those parsed as flags
        let content = "------ SEC LOG (/proc/sec_log) ------\n01-23 10:30:15.123 1234 5678 status=charging volt=4200 temp=234 -23 +123\n was the duration of 'SEC LOG (/proc/sec_log)' ------";
        let entries = BatteryParser::parse_battery_history(&content);
        // The regex won't match "-23" or "+123" (requires letter after +/-), so flags will be empty
        // Empty flags are valid, so entry will be parsed
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].flags.len(), 0); // No flags matched because -23 and +123 don't match the pattern
    }

    #[test]
    fn test_parse_battery_history_no_battery_data() {
        let content = "------ SEC LOG (/proc/sec_log) ------\n01-23 10:30:15.123 1234 5678 status=charging\n was the duration of 'SEC LOG (/proc/sec_log)' ------";
        let entries = BatteryParser::parse_battery_history(&content);
        // Should filter out entries without battery data (volt, temp, or charge)
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_battery_history_quoted_values() {
        let content = "------ SEC LOG (/proc/sec_log) ------\n01-23 10:30:15.123 1234 5678 status=\"charging\" volt=4200 temp=234\n was the duration of 'SEC LOG (/proc/sec_log)' ------";
        let entries = BatteryParser::parse_battery_history(&content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, Some("charging".to_string()));
    }

    #[test]
    fn test_full_parser_integration() {
        let mut data = create_test_battery_section().into_bytes();
        data.extend_from_slice(b"\n");
        data.extend_from_slice(create_test_kernel_log().as_bytes());
        data.extend_from_slice(b"\n");
        data.extend_from_slice(create_test_sec_log().as_bytes());
        
        let parser = BatteryParser::new().unwrap();
        let result = parser.parse(&data).unwrap();
        
        // Check apps
        let apps = result["apps"].as_array().unwrap();
        assert_eq!(apps.len(), 2);
        
        // Check version info
        assert!(result["version_info"].is_object());
        assert_eq!(result["version_info"]["sdk_version"], 36);
        
        // Check hardware info
        assert!(result["hardware_info"].is_object());
        let kernel_entries = result["hardware_info"]["kernel_log_entries"].as_array().unwrap();
        assert_eq!(kernel_entries.len(), 1);
        
        // Check battery history
        let history = result["battery_history"].as_array().unwrap();
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_parse_battery_section_skips_hsp() {
        let content = create_test_battery_section();
        let (apps, _) = BatteryParser::parse_battery_section(&content);
        
        // Should still parse apps correctly even with HSP records present
        assert_eq!(apps.len(), 2);
    }

    #[test]
    fn test_parse_battery_section_filters_low_uid() {
        let content = format!(
            "{}\n{}\n{}\n{}",
            "------ CHECKIN BATTERYSTATS (/system/bin/dumpsys -T 30000 batterystats -c) ------",
            "9,1000,l,pr,system.app",  // UID 1000 < 1010000, should be filtered
            "9,1010001,l,pr,user.app",  // UID 1010001 >= 1010000, should be parsed
            " was the duration of 'CHECKIN BATTERYSTATS' ------"
        );
        
        let (apps, _) = BatteryParser::parse_battery_section(&content);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].uid, 1010001);
        assert_eq!(apps[0].package_name, "user.app");
    }

    #[test]
    fn test_parse_kernel_battery_info_multiple_entries() {
        let content = format!(
            "{}\n{}\n{}\n{}",
            "------ KERNEL LOG (dmesg) ------",
            "[211662.753469] sec_bat_get_battery_info: Vm(4014mV) SOC(85%)",
            "[211663.123456] sec_bat_get_battery_info: Vm(4015mV) SOC(86%)",
            " was the duration of 'KERNEL LOG (dmesg)' ------"
        );
        
        let entries = BatteryParser::parse_kernel_battery_info(&content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].vm_mv, Some(4014));
        assert_eq!(entries[1].vm_mv, Some(4015));
    }

    #[test]
    fn test_parse_battery_history_with_all_fields() {
        let content = format!(
            "{}\n{}\n{}",
            "------ SEC LOG (/proc/sec_log) ------",
            "01-23 10:30:15.123 1234 5678 status=charging health=good plug=ac volt=4200 temp=234 current=500 charge=85 ap_temp=400 pa_temp=350 skin_temp=300 sub_batt_temp=200 +plugged +charging",
            " was the duration of 'SEC LOG (/proc/sec_log)' ------"
        );
        
        let entries = BatteryParser::parse_battery_history(&content);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.status, Some("charging".to_string()));
        assert_eq!(entry.health, Some("good".to_string()));
        assert_eq!(entry.plug, Some("ac".to_string()));
        assert_eq!(entry.volt, Some(4200));
        assert_eq!(entry.temp, Some(234));
        assert_eq!(entry.current, Some(500));
        assert_eq!(entry.charge, Some(85));
        assert_eq!(entry.ap_temp, Some(400));
        assert_eq!(entry.pa_temp, Some(350));
        assert_eq!(entry.skin_temp, Some(300));
        assert_eq!(entry.sub_batt_temp, Some(200));
    }
}