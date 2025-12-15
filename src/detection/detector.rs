// Exploitation Detector - With JSON Configuration Support
// Detects when applications have been remotely compromised or exploited

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// Import from battery_parser
use crate::parsers::battery_parser::AppBatteryStats;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitationIndicator {
    pub uid: u32,
    pub package_name: String,
    pub exploitation_type: ExploitationType,
    pub indicators: Vec<String>,
    pub confidence: f64,
    pub severity: SeverityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExploitationType {
    RemoteCodeExecution,
    CommandAndControl,
    DataExfiltration,
    RemoteAccessTrojan,
    Backdoor,
    PrivilegeEscalation,
    LateralMovement,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ExploitationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExploitationType::RemoteCodeExecution => write!(f, "Remote Code Execution (RCE)"),
            ExploitationType::CommandAndControl => write!(f, "Command & Control (C2)"),
            ExploitationType::DataExfiltration => write!(f, "Data Exfiltration"),
            ExploitationType::RemoteAccessTrojan => write!(f, "Remote Access Trojan (RAT)"),
            ExploitationType::Backdoor => write!(f, "Backdoor"),
            ExploitationType::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            ExploitationType::LateralMovement => write!(f, "Lateral Movement"),
            ExploitationType::Unknown => write!(f, "Unknown"),
        }
    }
}

pub struct ExploitationDetector {
    pub config: DetectorConfig,
}

/// Main configuration structure - can be loaded from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    #[serde(default)]
    pub description: Option<String>,
    
    pub rce: RceConfig,
    pub c2: C2Config,
    pub exfiltration: ExfiltrationConfig,
    pub rat: RatConfig,
    pub backdoor: BackdoorConfig,
    pub privilege_escalation: PrivilegeEscalationConfig,
    pub lateral_movement: LateralMovementConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RceConfig {
    pub suspicious_cpu_system_ratio: f64,
    pub min_system_cpu_ms: u32,
    pub unexpected_process_spawn_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    pub beaconing_alarm_count: u32,
    pub beaconing_avg_duration_ms: u64,
    pub regular_interval_variance: f64,
    pub gcm_abuse_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationConfig {
    pub tx_rx_ratio: f64,
    pub min_upload_bytes: u64,
    pub cellular_preference_ratio: f64,
    pub background_upload_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatConfig {
    pub persistent_service_hours: f64,
    pub wakelock_frequency: u32,
    pub screen_capture_indicators: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackdoorConfig {
    pub boot_receiver_count: u32,
    pub hidden_service_time_ms: u64,
    pub debugging_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscalationConfig {
    pub system_cpu_ratio: f64,
    pub root_access_indicators: bool,
    pub permission_escalation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementConfig {
    pub ipc_abuse_count: u32,
    pub data_access_other_apps: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            description: Some("Default configuration".to_string()),
            rce: RceConfig {
                suspicious_cpu_system_ratio: 4.0,
                min_system_cpu_ms: 30_000,
                unexpected_process_spawn_count: 10,
            },
            c2: C2Config {
                beaconing_alarm_count: 100,
                beaconing_avg_duration_ms: 500,
                regular_interval_variance: 0.3,
                gcm_abuse_count: 50,
            },
            exfiltration: ExfiltrationConfig {
                tx_rx_ratio: 3.0,
                min_upload_bytes: 50_000_000,
                cellular_preference_ratio: 2.5,
                background_upload_threshold: 20_000_000,
            },
            rat: RatConfig {
                persistent_service_hours: 6.0,
                wakelock_frequency: 250,
                screen_capture_indicators: true,
            },
            backdoor: BackdoorConfig {
                boot_receiver_count: 3,
                hidden_service_time_ms: 21_600_000,
                debugging_enabled: true,
            },
            privilege_escalation: PrivilegeEscalationConfig {
                system_cpu_ratio: 3.5,
                root_access_indicators: true,
                permission_escalation: true,
            },
            lateral_movement: LateralMovementConfig {
                ipc_abuse_count: 20,
                data_access_other_apps: true,
            },
        }
    }
}

impl DetectorConfig {
    /// Load configuration from JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: DetectorConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }
    
    /// Save configuration to JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
    
    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: DetectorConfig = serde_json::from_str(json)?;
        Ok(config)
    }
    
    /// Convert configuration to JSON string
    pub fn to_json(&self) -> Result<String, Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(json)
    }
    
    /// Create a strict configuration (high security)
    pub fn strict() -> Self {
        Self {
            description: Some("Strict configuration for high-security environments".to_string()),
            rce: RceConfig {
                suspicious_cpu_system_ratio: 3.0,
                min_system_cpu_ms: 20_000,
                unexpected_process_spawn_count: 6,
            },
            c2: C2Config {
                beaconing_alarm_count: 50,
                beaconing_avg_duration_ms: 400,
                regular_interval_variance: 0.25,
                gcm_abuse_count: 30,
            },
            exfiltration: ExfiltrationConfig {
                tx_rx_ratio: 2.0,
                min_upload_bytes: 30_000_000,
                cellular_preference_ratio: 2.0,
                background_upload_threshold: 10_000_000,
            },
            rat: RatConfig {
                persistent_service_hours: 4.0,
                wakelock_frequency: 150,
                screen_capture_indicators: true,
            },
            backdoor: BackdoorConfig {
                boot_receiver_count: 2,
                hidden_service_time_ms: 14_400_000,
                debugging_enabled: true,
            },
            privilege_escalation: PrivilegeEscalationConfig {
                system_cpu_ratio: 3.0,
                root_access_indicators: true,
                permission_escalation: true,
            },
            lateral_movement: LateralMovementConfig {
                ipc_abuse_count: 15,
                data_access_other_apps: true,
            },
        }
    }
    
    /// Create a lenient configuration (corporate/MDM)
    pub fn lenient() -> Self {
        Self {
            description: Some("Lenient configuration for corporate/MDM environments".to_string()),
            rce: RceConfig {
                suspicious_cpu_system_ratio: 5.0,
                min_system_cpu_ms: 40_000,
                unexpected_process_spawn_count: 15,
            },
            c2: C2Config {
                beaconing_alarm_count: 200,
                beaconing_avg_duration_ms: 600,
                regular_interval_variance: 0.4,
                gcm_abuse_count: 100,
            },
            exfiltration: ExfiltrationConfig {
                tx_rx_ratio: 4.0,
                min_upload_bytes: 100_000_000,
                cellular_preference_ratio: 3.0,
                background_upload_threshold: 50_000_000,
            },
            rat: RatConfig {
                persistent_service_hours: 12.0,
                wakelock_frequency: 400,
                screen_capture_indicators: true,
            },
            backdoor: BackdoorConfig {
                boot_receiver_count: 5,
                hidden_service_time_ms: 43_200_000,
                debugging_enabled: true,
            },
            privilege_escalation: PrivilegeEscalationConfig {
                system_cpu_ratio: 4.5,
                root_access_indicators: true,
                permission_escalation: true,
            },
            lateral_movement: LateralMovementConfig {
                ipc_abuse_count: 40,
                data_access_other_apps: true,
            },
        }
    }
}

impl ExploitationDetector {
    /// Create detector with default configuration
    pub fn new() -> Self {
        Self {
            config: DetectorConfig::default(),
        }
    }
    
    /// Create detector with custom configuration
    pub fn with_config(config: DetectorConfig) -> Self {
        Self { config }
    }
    
    /// Create detector by loading configuration from JSON file
    pub fn from_config_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let config = DetectorConfig::from_file(path)?;
        Ok(Self { config })
    }
    
    /// Create detector with strict configuration
    pub fn strict() -> Self {
        Self {
            config: DetectorConfig::strict(),
        }
    }
    
    /// Create detector with lenient configuration
    pub fn lenient() -> Self {
        Self {
            config: DetectorConfig::lenient(),
        }
    }
    
    /// Main detection entry point
    pub fn detect_exploitation(&self, apps: &[AppBatteryStats]) -> Vec<ExploitationIndicator> {
        apps.iter()
            .filter_map(|app| self.analyze_app(app))
            .collect()
    }
    
    /// Analyze a single app for remote exploitation indicators
    pub fn analyze_app(&self, app: &AppBatteryStats) -> Option<ExploitationIndicator> {
        let mut all_indicators = Vec::new();
        
        // Run all remote exploitation detection functions
        all_indicators.extend(self.detect_remote_code_execution(app));
        all_indicators.extend(self.detect_command_and_control(app));
        all_indicators.extend(self.detect_data_exfiltration(app));
        all_indicators.extend(self.detect_remote_access_trojan(app));
        all_indicators.extend(self.detect_backdoor(app));
        all_indicators.extend(self.detect_privilege_escalation(app));
        all_indicators.extend(self.detect_lateral_movement(app));
        
        if !all_indicators.is_empty() {
            let exploitation_type = self.classify_exploitation(&all_indicators);
            let severity = self.calculate_severity(&all_indicators, &exploitation_type);
            let confidence = self.calculate_confidence(&all_indicators, &exploitation_type);
            
            Some(ExploitationIndicator {
                uid: app.uid,
                package_name: app.package_name.clone(),
                exploitation_type,
                indicators: all_indicators,
                confidence,
                severity,
            })
        } else {
            None
        }
    }
    
    // ... (rest of detection methods remain the same, but now use self.config.rce.xxx, self.config.c2.xxx, etc.)
    
    pub fn detect_remote_code_execution(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        let legitimate_cpu_apps = [
            "chrome", "firefox", "games", "video", "camera",
            "maps", "youtube", "netflix", "spotify", "browser"
        ];
        
        let package_lower = app.package_name.to_lowercase();
        let is_legitimate = legitimate_cpu_apps.iter()
            .any(|&app_type| package_lower.contains(app_type));
        
        if app.cpu_user_time_ms > 0 {
            let cpu_ratio = app.cpu_system_time_ms as f64 / app.cpu_user_time_ms as f64;
            
            if cpu_ratio > self.config.rce.suspicious_cpu_system_ratio 
                && app.cpu_system_time_ms > self.config.rce.min_system_cpu_ms 
                && !is_legitimate {
                indicators.push(format!(
                    "RCE indicator: Abnormal system CPU usage - {}ms system vs {}ms user (ratio {:.2}:1) - suggests injected code execution",
                    app.cpu_system_time_ms,
                    app.cpu_user_time_ms,
                    cpu_ratio
                ));
            }
        }
        
        let spawn_indicators = ["exec", "fork", "process", "runtime"];
        let spawn_count: u32 = app.background_jobs.iter()
            .filter(|job| {
                let job_lower = job.name.to_lowercase();
                spawn_indicators.iter().any(|&ind| job_lower.contains(ind))
            })
            .map(|job| job.count)
            .sum();
        
        if spawn_count > self.config.rce.unexpected_process_spawn_count {
            indicators.push(format!(
                "RCE indicator: Excessive process spawning - {} process-related jobs - may indicate code injection",
                spawn_count
            ));
        }
        
        indicators
    }
    
    pub fn detect_command_and_control(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        for wakelock in &app.wakelocks {
            if wakelock.name.contains("*alarm*") 
                && wakelock.count > self.config.c2.beaconing_alarm_count {
                let avg_duration = if wakelock.count > 0 {
                    wakelock.time_ms / wakelock.count as u64
                } else {
                    0
                };
                
                if avg_duration < self.config.c2.beaconing_avg_duration_ms {
                    indicators.push(format!(
                        "C2 indicator: Regular beaconing pattern detected - {} alarm-based wakeups, avg {:.2}ms each - consistent with automated C2 callbacks",
                        wakelock.count,
                        avg_duration
                    ));
                }
            }
        }
        
        for job in &app.background_jobs {
            let job_lower = job.name.to_lowercase();
            if (job_lower.contains("c2dm") || job_lower.contains("gcm") || job_lower.contains("fcm"))
                && job.count > self.config.c2.gcm_abuse_count {
                indicators.push(format!(
                    "C2 indicator: Push notification infrastructure abuse - {} GCM/FCM events - may be using Google services for command delivery",
                    job.count
                ));
            }
        }
        
        let short_frequent_jobs: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                let avg_time = job.time_ms / job.count.max(1) as u64;
                avg_time < 200 && job.count > 50
            })
            .collect();
        
        if !short_frequent_jobs.is_empty() {
            let total_polls: u32 = short_frequent_jobs.iter().map(|j| j.count).sum();
            indicators.push(format!(
                "C2 indicator: Rapid polling behavior - {} short jobs (<200ms) with {} total polls - consistent with command polling",
                short_frequent_jobs.len(),
                total_polls
            ));
        }
        
        indicators
    }
    
    pub fn detect_data_exfiltration(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        let total_tx = app.network_tx_mobile + app.network_tx_wifi;
        let total_rx = app.network_rx_mobile + app.network_rx_wifi;
        
        if total_tx > 0 && total_rx > 0 {
            let tx_rx_ratio = total_tx as f64 / total_rx as f64;
            
            if tx_rx_ratio > self.config.exfiltration.tx_rx_ratio 
                && total_tx > self.config.exfiltration.min_upload_bytes {
                indicators.push(format!(
                    "Exfiltration indicator: Upload-heavy traffic - {:.2}x more uploads than downloads ({:.2} MB uploaded) - consistent with data theft",
                    tx_rx_ratio,
                    total_tx as f64 / (1024.0 * 1024.0)
                ));
            }
        }
        
        if app.network_tx_mobile > 0 && app.network_tx_wifi > 0 {
            let cellular_ratio = app.network_tx_mobile as f64 / app.network_tx_wifi as f64;
            
            if cellular_ratio > self.config.exfiltration.cellular_preference_ratio 
                && app.network_tx_mobile > self.config.exfiltration.background_upload_threshold {
                indicators.push(format!(
                    "Exfiltration indicator: Cellular network preference - {:.2}x more data via cellular ({:.2} MB) vs WiFi ({:.2} MB) - may be avoiding network monitoring",
                    cellular_ratio,
                    app.network_tx_mobile as f64 / (1024.0 * 1024.0),
                    app.network_tx_wifi as f64 / (1024.0 * 1024.0)
                ));
            }
        }
        
        if app.network_tx_mobile + app.network_tx_wifi > self.config.exfiltration.background_upload_threshold {
            let background_service_active = app.foreground_service_time_ms > 0 || app.total_job_count > 10;
            
            if background_service_active {
                indicators.push(format!(
                    "Exfiltration indicator: Large background data transmission - {:.2} MB uploaded with {} background jobs - consistent with automated data theft",
                    (app.network_tx_mobile + app.network_tx_wifi) as f64 / (1024.0 * 1024.0),
                    app.total_job_count
                ));
            }
        }
        
        indicators
    }
    
    pub fn detect_remote_access_trojan(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        let service_hours = app.foreground_service_time_ms as f64 / (1000.0 * 60.0 * 60.0);
        
        if service_hours > self.config.rat.persistent_service_hours {
            indicators.push(format!(
                "RAT indicator: Long-running foreground service - {:.2} hours continuous - may be maintaining remote access session",
                service_hours
            ));
        }
        
        let total_wakelock_count: u32 = app.wakelocks.iter()
            .map(|w| w.count)
            .sum();
        
        if total_wakelock_count > self.config.rat.wakelock_frequency {
            indicators.push(format!(
                "RAT indicator: Extremely frequent wake patterns - {} total wakelock acquisitions - consistent with maintaining responsive remote control",
                total_wakelock_count
            ));
        }
        
        let capture_keywords = ["screen", "capture", "media", "display", "surface"];
        let capture_jobs: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                let job_lower = job.name.to_lowercase();
                capture_keywords.iter().any(|&kw| job_lower.contains(kw))
            })
            .collect();
        
        if !capture_jobs.is_empty() && self.config.rat.screen_capture_indicators {
            let total_captures: u32 = capture_jobs.iter().map(|j| j.count).sum();
            indicators.push(format!(
                "RAT indicator: Screen/media capture activity - {} capture-related jobs with {} total executions - may be streaming screen to attacker",
                capture_jobs.len(),
                total_captures
            ));
        }
        
        indicators
    }
    
    pub fn detect_backdoor(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        let boot_receivers: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                job.name.contains("BOOT_COMPLETED") || 
                job.name.contains("LOCKED_BOOT_COMPLETED") ||
                job.name.contains("QUICKBOOT_POWERON")
            })
            .collect();
        
        if !boot_receivers.is_empty() {
            let boot_count: u32 = boot_receivers.iter().map(|j| j.count).sum();
            
            if boot_count >= self.config.backdoor.boot_receiver_count {
                indicators.push(format!(
                    "Backdoor indicator: Persistent boot receiver - {} boot completion events - ensures backdoor survives reboots",
                    boot_count
                ));
            }
        }
        
        if app.foreground_service_time_ms > self.config.backdoor.hidden_service_time_ms 
            && app.total_job_count > 0 {
            indicators.push(format!(
                "Backdoor indicator: Hidden persistent service - {:.2} hours of service time with background activity - consistent with backdoor maintenance",
                app.foreground_service_time_ms as f64 / (1000.0 * 60.0 * 60.0)
            ));
        }
        
        let update_jobs: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                job.name.contains("PACKAGE_REPLACED") ||
                job.name.contains("PACKAGE_ADDED") ||
                job.name.contains("MY_PACKAGE_REPLACED")
            })
            .collect();
        
        if !update_jobs.is_empty() {
            let update_count: u32 = update_jobs.iter().map(|j| j.count).sum();
            
            if update_count > 5 {
                indicators.push(format!(
                    "Backdoor indicator: Package update monitoring - {} package modification events - may be updating backdoor code remotely",
                    update_count
                ));
            }
        }
        
        indicators
    }
    
    pub fn detect_privilege_escalation(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        if app.cpu_user_time_ms > 0 {
            let cpu_ratio = app.cpu_system_time_ms as f64 / app.cpu_user_time_ms as f64;
            
            if cpu_ratio > self.config.privilege_escalation.system_cpu_ratio 
                && app.cpu_system_time_ms > 30_000 {
                indicators.push(format!(
                    "Privilege escalation indicator: System call dominance - {}ms system vs {}ms user (ratio {:.2}:1) - may be exploiting kernel vulnerabilities",
                    app.cpu_system_time_ms,
                    app.cpu_user_time_ms,
                    cpu_ratio
                ));
            }
        }
        
        let root_keywords = ["su", "root", "superuser", "privilege", "admin", "elevated"];
        let root_jobs: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                let job_lower = job.name.to_lowercase();
                root_keywords.iter().any(|&kw| job_lower.contains(kw))
            })
            .collect();
        
        if !root_jobs.is_empty() && self.config.privilege_escalation.root_access_indicators {
            indicators.push(format!(
                "Privilege escalation indicator: Root access attempts - {} root-related jobs detected - attempting to gain elevated privileges",
                root_jobs.len()
            ));
        }
        
        indicators
    }
    
    pub fn detect_lateral_movement(&self, app: &AppBatteryStats) -> Vec<String> {
        let mut indicators = Vec::new();
        
        let ipc_keywords = ["bind", "service", "intent", "broadcast", "provider", "ipc"];
        let ipc_jobs: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                let job_lower = job.name.to_lowercase();
                ipc_keywords.iter().any(|&kw| job_lower.contains(kw))
            })
            .collect();
        
        if !ipc_jobs.is_empty() {
            let ipc_count: u32 = ipc_jobs.iter().map(|j| j.count).sum();
            
            if ipc_count > self.config.lateral_movement.ipc_abuse_count {
                indicators.push(format!(
                    "Lateral movement indicator: Excessive IPC activity - {} IPC-related jobs with {} total calls - may be accessing other applications",
                    ipc_jobs.len(),
                    ipc_count
                ));
            }
        }
        
        let provider_jobs: Vec<_> = app.background_jobs.iter()
            .filter(|job| {
                job.name.to_lowercase().contains("content") ||
                job.name.to_lowercase().contains("provider")
            })
            .collect();
        
        if !provider_jobs.is_empty() && provider_jobs.len() > 5 {
            indicators.push(format!(
                "Lateral movement indicator: Content provider access - {} content provider interactions - may be reading data from other apps",
                provider_jobs.len()
            ));
        }
        
        indicators
    }
    
    pub fn classify_exploitation(&self, indicators: &[String]) -> ExploitationType {
        let mut rce_score = 0;
        let mut c2_score = 0;
        let mut exfil_score = 0;
        let mut rat_score = 0;
        let mut backdoor_score = 0;
        let mut privesc_score = 0;
        let mut lateral_score = 0;
        
        for indicator in indicators {
            let ind_lower = indicator.to_lowercase();
            
            if ind_lower.contains("rce indicator") || ind_lower.contains("code execution") {
                rce_score += 3;
            }
            if ind_lower.contains("c2 indicator") || ind_lower.contains("beaconing") {
                c2_score += 2;
            }
            if ind_lower.contains("exfiltration indicator") || ind_lower.contains("upload") {
                exfil_score += 2;
            }
            if ind_lower.contains("rat indicator") || ind_lower.contains("remote access") {
                rat_score += 2;
            }
            if ind_lower.contains("backdoor indicator") || ind_lower.contains("persistence") {
                backdoor_score += 2;
            }
            if ind_lower.contains("privilege escalation") || ind_lower.contains("root") {
                privesc_score += 2;
            }
            if ind_lower.contains("lateral movement") || ind_lower.contains("ipc") {
                lateral_score += 1;
            }
        }
        
        let max_score = rce_score.max(c2_score)
            .max(exfil_score)
            .max(rat_score)
            .max(backdoor_score)
            .max(privesc_score)
            .max(lateral_score);
        
        if max_score == 0 {
            ExploitationType::Unknown
        } else if max_score == rce_score {
            ExploitationType::RemoteCodeExecution
        } else if max_score == c2_score {
            ExploitationType::CommandAndControl
        } else if max_score == exfil_score {
            ExploitationType::DataExfiltration
        } else if max_score == rat_score {
            ExploitationType::RemoteAccessTrojan
        } else if max_score == backdoor_score {
            ExploitationType::Backdoor
        } else if max_score == privesc_score {
            ExploitationType::PrivilegeEscalation
        } else {
            ExploitationType::LateralMovement
        }
    }
    
    pub fn calculate_severity(&self, indicators: &[String], exploitation_type: &ExploitationType) -> SeverityLevel {
        let indicator_count = indicators.len();
        
        let base_severity = match exploitation_type {
            ExploitationType::RemoteCodeExecution => 6,      // Critical base
            ExploitationType::RemoteAccessTrojan => 6,       // Critical base
            ExploitationType::Backdoor => 6,                 // Critical base
            ExploitationType::CommandAndControl => 4,        // High base
            ExploitationType::DataExfiltration => 4,         // High base
            ExploitationType::PrivilegeEscalation => 4,      // High base
            ExploitationType::LateralMovement => 2,          // Medium base
            ExploitationType::Unknown => 1,                  // Low base
        };
        
        let adjusted_severity = base_severity + (indicator_count / 3) as i32;
        
        match adjusted_severity {
            0..=1 => SeverityLevel::Low,
            2..=3 => SeverityLevel::Medium,
            4..=5 => SeverityLevel::High,
            _ => SeverityLevel::Critical,
        }
    }
    
    pub fn calculate_confidence(&self, indicators: &[String], exploitation_type: &ExploitationType) -> f64 {
        let base_confidence = (indicators.len() as f64 * 0.15).min(0.7);
        let mut confidence = base_confidence;
        
        for indicator in indicators {
            let ind_lower = indicator.to_lowercase();
            
            if ind_lower.contains("rce indicator") || ind_lower.contains("code execution") {
                confidence += 0.18;
            }
            if ind_lower.contains("c2 indicator") && ind_lower.contains("beaconing") {
                confidence += 0.15;
            }
            if ind_lower.contains("upload-heavy") && ind_lower.contains("exfiltration") {
                confidence += 0.12;
            }
            if ind_lower.contains("backdoor") && ind_lower.contains("persistence") {
                confidence += 0.14;
            }
            if ind_lower.contains("rat indicator") && ind_lower.contains("remote access") {
                confidence += 0.16;
            }
        }
        
        match exploitation_type {
            ExploitationType::RemoteCodeExecution | 
            ExploitationType::CommandAndControl |
            ExploitationType::RemoteAccessTrojan => {
                confidence *= 1.15;
            }
            ExploitationType::Unknown => {
                confidence *= 0.5;
            }
            _ => {}
        }
        
        confidence.min(0.95)
    }
}

impl Default for ExploitationDetector {
    fn default() -> Self {
        Self::new()
    }
}

