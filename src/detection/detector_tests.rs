// Comprehensive Test Suite for Remote Exploitation Detector

#[cfg(test)]
mod exploitation_detector_tests {
    use crate::detection::detector::{ExploitationDetector, SeverityLevel, ExploitationType};
    use crate::parsers::battery_parser::{AppBatteryStats, BackgroundJob, Wakelock};
        
    // Helper function to create a clean test app
    fn create_clean_app(uid: u32, package: &str) -> AppBatteryStats {
        AppBatteryStats {
            uid,
            package_name: package.to_string(),
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
        }
    }
    
    // ==================== REMOTE CODE EXECUTION TESTS ====================
    
    #[test]
    fn test_rce_high_system_cpu_ratio() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010001, "com.example.exploited");
        
        // Abnormal: 5:1 system to user ratio
        app.cpu_user_time_ms = 10_000;
        app.cpu_system_time_ms = 50_000;
        
        let indicators = detector.detect_remote_code_execution(&app);
        
        assert!(!indicators.is_empty(), "Should detect RCE with high system CPU ratio");
        assert!(indicators[0].contains("RCE indicator"));
        assert!(indicators[0].contains("ratio 5.00:1"));
    }
    
    #[test]
    fn test_rce_normal_cpu_ratio_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010002, "com.example.normal");
        
        // Normal: 1:5 system to user ratio (user dominates)
        app.cpu_user_time_ms = 50_000;
        app.cpu_system_time_ms = 10_000;
        
        let indicators = detector.detect_remote_code_execution(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect RCE with normal CPU ratio");
    }
    
    #[test]
    fn test_rce_process_spawning() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010003, "com.example.spawner");
        
        // Multiple process-related jobs
        app.background_jobs.push(BackgroundJob {
            name: "exec_helper".to_string(),
            time_ms: 1000,
            count: 5,
        });
        app.background_jobs.push(BackgroundJob {
            name: "fork_process".to_string(),
            time_ms: 800,
            count: 4,
        });
        app.background_jobs.push(BackgroundJob {
            name: "runtime_spawn".to_string(),
            time_ms: 600,
            count: 3,
        });
        app.total_job_count = 12;
        
        let indicators = detector.detect_remote_code_execution(&app);
        
        assert!(!indicators.is_empty(), "Should detect RCE with process spawning");
        assert!(indicators[0].contains("process spawning"));
        assert!(indicators[0].contains("12 process-related jobs"));
    }
    
    #[test]
    fn test_rce_edge_case_exactly_threshold() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010004, "com.example.edge");
        
        // Exactly at threshold (4:1 ratio)
        app.cpu_user_time_ms = 10_000;
        app.cpu_system_time_ms = 40_000;
        
        let indicators = detector.detect_remote_code_execution(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect at exact threshold (needs >)");
    }
    
    #[test]
    fn test_rce_combined_indicators() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010005, "com.example.fullrce");
        
        // High system CPU + process spawning
        app.cpu_user_time_ms = 8_000;
        app.cpu_system_time_ms = 45_000; // 5.6:1 ratio
        
        app.background_jobs.push(BackgroundJob {
            name: "exec_native".to_string(),
            time_ms: 2000,
            count: 6,
        });
        app.background_jobs.push(BackgroundJob {
            name: "fork_helper".to_string(),
            time_ms: 1500,
            count: 5,
        });
        app.total_job_count = 11;
        
        let indicators = detector.detect_remote_code_execution(&app);
        
        assert_eq!(indicators.len(), 2, "Should detect both RCE indicators");
        assert!(indicators[0].contains("system CPU"));
        assert!(indicators[1].contains("process spawning"));
    }
    
    // ==================== COMMAND & CONTROL TESTS ====================
    
    #[test]
    fn test_c2_regular_beaconing() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010010, "com.example.c2app");
        
        // Regular alarm-based beaconing
        app.wakelocks.push(Wakelock {
            name: "*alarm*".to_string(),
            wakelock_type: "p".to_string(),
            time_ms: 40_000, // 40 seconds total
            count: 150,      // 150 wakeups
            current_duration_ms: 0,
            max_duration_ms: 350,
        });
        
        let indicators = detector.detect_command_and_control(&app);
        
        assert!(!indicators.is_empty(), "Should detect C2 beaconing");
        assert!(indicators[0].contains("C2 indicator"));
        assert!(indicators[0].contains("150 alarm-based wakeups"));
    }
    
    #[test]
    fn test_c2_below_threshold_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010011, "com.example.normal");
        
        // Below threshold (only 50 alarms)
        app.wakelocks.push(Wakelock {
            name: "*alarm*".to_string(),
            wakelock_type: "p".to_string(),
            time_ms: 10_000,
            count: 50,
            current_duration_ms: 0,
            max_duration_ms: 200,
        });
        
        let indicators = detector.detect_command_and_control(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect C2 with low alarm count");
    }
    
    #[test]
    fn test_c2_gcm_abuse() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010012, "com.example.gcmabuse");
        
        // Excessive GCM/FCM usage
        app.background_jobs.push(BackgroundJob {
            name: "com.google.android.c2dm.intent.RECEIVE".to_string(),
            time_ms: 5000,
            count: 60,
        });
        app.total_job_count = 60;
        
        let indicators = detector.detect_command_and_control(&app);
        
        assert!(!indicators.is_empty(), "Should detect C2 GCM abuse");
        assert!(indicators[0].contains("GCM/FCM"));
        assert!(indicators[0].contains("60"));
    }
    
    #[test]
    fn test_c2_rapid_polling() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010013, "com.example.polling");
        
        // Short jobs with high count (rapid polling)
        // Each job needs: avg_time < 200ms AND count > 50
        app.background_jobs.push(BackgroundJob {
            name: "poll_service_1".to_string(),
            time_ms: 8000,  // 8 seconds total
            count: 60,      // avg 133ms per job
        });
        app.background_jobs.push(BackgroundJob {
            name: "poll_service_2".to_string(),
            time_ms: 7000,  // 7 seconds total
            count: 55,      // avg 127ms per job
        });
        app.total_job_count = 115;
        app.total_job_time_ms = 15_000;
        
        let indicators = detector.detect_command_and_control(&app);
        
        assert!(!indicators.is_empty(), "Should detect C2 rapid polling");
        assert!(indicators[0].contains("Rapid polling"));
        assert!(indicators[0].contains("115 total polls"));
    }
    
    #[test]
    fn test_c2_all_indicators_combined() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010014, "com.example.fullc2");
        
        // Beaconing
        app.wakelocks.push(Wakelock {
            name: "*alarm*".to_string(),
            wakelock_type: "p".to_string(),
            time_ms: 30_000,
            count: 180,
            current_duration_ms: 0,
            max_duration_ms: 300,
        });
        
        // GCM abuse
        app.background_jobs.push(BackgroundJob {
            name: "com.google.android.gcm.RECEIVE".to_string(),
            time_ms: 3000,
            count: 70,
        });
        
        // Rapid polling
        for i in 0..8 {
            app.background_jobs.push(BackgroundJob {
                name: format!("check_command_{}", i),
                time_ms: 1200,
                count: 8,
            });
        }
        app.total_job_count = 134;
        
        let indicators = detector.detect_command_and_control(&app);
        
        assert!(indicators.len() >= 2, "Should detect multiple C2 indicators");
    }
    
    // ==================== DATA EXFILTRATION TESTS ====================
    
    #[test]
    fn test_exfil_upload_heavy_traffic() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010020, "com.example.exfil");
        
        // Upload-heavy: 5:1 ratio, >50MB
        app.network_tx_mobile = 200_000_000; // 200 MB upload
        app.network_rx_mobile = 40_000_000;  // 40 MB download
        app.network_tx_wifi = 50_000_000;
        app.network_rx_wifi = 10_000_000;
        
        let indicators = detector.detect_data_exfiltration(&app);
        
        assert!(!indicators.is_empty(), "Should detect exfiltration");
        assert!(indicators[0].contains("Upload-heavy traffic"));
        assert!(indicators[0].contains("5.00x"));
    }
    
    #[test]
    fn test_exfil_normal_ratio_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010021, "com.example.normal");
        
        // Normal: Download-heavy (1:5 upload:download)
        app.network_tx_mobile = 20_000_000;
        app.network_rx_mobile = 100_000_000;
        
        let indicators = detector.detect_data_exfiltration(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect with normal ratio");
    }
    
    #[test]
    fn test_exfil_cellular_preference() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010022, "com.example.cellular");
        
        // Prefers cellular over WiFi (avoiding monitoring)
        app.network_tx_mobile = 150_000_000; // 150 MB cellular
        app.network_tx_wifi = 30_000_000;    // 30 MB WiFi
        app.network_rx_mobile = 10_000_000;
        app.network_rx_wifi = 5_000_000;
        
        let indicators = detector.detect_data_exfiltration(&app);
        
        assert!(!indicators.is_empty(), "Should detect cellular preference");
        // Note: May also detect upload-heavy (12:1 ratio), so cellular preference could be [1]
        let cellular_indicator = indicators.iter()
            .find(|i| i.contains("Cellular network preference"))
            .expect("Should find cellular preference indicator");
        assert!(cellular_indicator.contains("5.00x"));
    }
    
    #[test]
    fn test_exfil_large_background_uploads() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010023, "com.example.background");
        
        // Large uploads with background activity
        app.network_tx_mobile = 30_000_000;
        app.network_tx_wifi = 80_000_000;
        app.network_rx_mobile = 5_000_000;
        app.network_rx_wifi = 10_000_000;
        
        // Background activity indicators
        app.background_jobs.push(BackgroundJob {
            name: "upload_service".to_string(),
            time_ms: 10000,
            count: 15,
        });
        app.total_job_count = 15;
        
        let indicators = detector.detect_data_exfiltration(&app);
        
        assert!(!indicators.is_empty(), "Should detect background uploads");
        assert!(indicators.iter().any(|i| i.contains("background")));
    }
    
    #[test]
    fn test_exfil_all_indicators() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010024, "com.example.fullexfil");
        
        // Upload-heavy
        app.network_tx_mobile = 180_000_000;
        app.network_tx_wifi = 40_000_000;
        app.network_rx_mobile = 20_000_000;
        app.network_rx_wifi = 10_000_000;
        
        // Background jobs
        app.background_jobs.push(BackgroundJob {
            name: "data_sync".to_string(),
            time_ms: 8000,
            count: 12,
        });
        app.total_job_count = 12;
        
        let indicators = detector.detect_data_exfiltration(&app);
        
        assert!(indicators.len() >= 2, "Should detect multiple exfiltration indicators");
    }
    
    // ==================== REMOTE ACCESS TROJAN TESTS ====================
    
    #[test]
    fn test_rat_persistent_service() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010030, "com.example.rat");
        
        // Long-running foreground service (8 hours)
        app.foreground_service_time_ms = 28_800_000; // 8 hours
        
        let indicators = detector.detect_remote_access_trojan(&app);
        
        assert!(!indicators.is_empty(), "Should detect RAT persistent service");
        assert!(indicators[0].contains("RAT indicator"));
        assert!(indicators[0].contains("8.00 hours"));
    }
    
    #[test]
    fn test_rat_short_service_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010031, "com.example.normal");
        
        // Short service (2 hours, below 6 hour threshold)
        app.foreground_service_time_ms = 7_200_000;
        
        let indicators = detector.detect_remote_access_trojan(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect RAT with short service");
    }
    
    #[test]
    fn test_rat_frequent_wakelocks() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010032, "com.example.responsive");
        
        // Very frequent wakelocks
        app.wakelocks.push(Wakelock {
            name: "keep_alive".to_string(),
            wakelock_type: "p".to_string(),
            time_ms: 50_000,
            count: 180,
            current_duration_ms: 0,
            max_duration_ms: 500,
        });
        app.wakelocks.push(Wakelock {
            name: "network_check".to_string(),
            wakelock_type: "p".to_string(),
            time_ms: 30_000,
            count: 120,
            current_duration_ms: 0,
            max_duration_ms: 400,
        });
        
        let indicators = detector.detect_remote_access_trojan(&app);
        
        assert!(!indicators.is_empty(), "Should detect RAT frequent wakelocks");
        assert!(indicators[0].contains("300 total wakelock acquisitions"));
    }
    
    #[test]
    fn test_rat_screen_capture() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010033, "com.example.capture");
        
        // Screen capture activity
        app.background_jobs.push(BackgroundJob {
            name: "screen_capture_service".to_string(),
            time_ms: 15000,
            count: 45,
        });
        app.background_jobs.push(BackgroundJob {
            name: "media_projection".to_string(),
            time_ms: 10000,
            count: 30,
        });
        app.background_jobs.push(BackgroundJob {
            name: "display_monitor".to_string(),
            time_ms: 8000,
            count: 25,
        });
        app.total_job_count = 100;
        
        let indicators = detector.detect_remote_access_trojan(&app);
        
        assert!(!indicators.is_empty(), "Should detect RAT screen capture");
        assert!(indicators[0].contains("Screen/media capture"));
        assert!(indicators[0].contains("100 total executions"));
    }
    
    #[test]
    fn test_rat_full_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010034, "com.example.fullrat");
        
        // All RAT indicators
        app.foreground_service_time_ms = 43_200_000; // 12 hours
        
        // Frequent wakelocks
        app.wakelocks.push(Wakelock {
            name: "remote_session".to_string(),
            wakelock_type: "p".to_string(),
            time_ms: 80_000,
            count: 300,
            current_duration_ms: 0,
            max_duration_ms: 500,
        });
        
        // Screen capture
        app.background_jobs.push(BackgroundJob {
            name: "screen_stream".to_string(),
            time_ms: 20000,
            count: 60,
        });
        app.total_job_count = 60;
        
        let indicators = detector.detect_remote_access_trojan(&app);
        
        assert!(indicators.len() >= 3, "Should detect all RAT indicators");
    }
    
    // ==================== BACKDOOR TESTS ====================
    
    #[test]
    fn test_backdoor_boot_receiver() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010040, "com.example.backdoor");
        
        // Boot completion receivers
        app.background_jobs.push(BackgroundJob {
            name: "android.intent.action.BOOT_COMPLETED".to_string(),
            time_ms: 2000,
            count: 3,
        });
        app.background_jobs.push(BackgroundJob {
            name: "android.intent.action.LOCKED_BOOT_COMPLETED".to_string(),
            time_ms: 1500,
            count: 2,
        });
        app.total_job_count = 5;
        
        let indicators = detector.detect_backdoor(&app);
        
        assert!(!indicators.is_empty(), "Should detect backdoor boot receiver");
        assert!(indicators[0].contains("Backdoor indicator"));
        assert!(indicators[0].contains("boot completion events"));
    }
    
    #[test]
    fn test_backdoor_single_boot_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010041, "com.example.normal");
        
        // Only one boot event (normal)
        app.background_jobs.push(BackgroundJob {
            name: "android.intent.action.BOOT_COMPLETED".to_string(),
            time_ms: 1000,
            count: 1,
        });
        app.total_job_count = 1;
        
        let indicators = detector.detect_backdoor(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect with single boot event");
    }
    
    #[test]
    fn test_backdoor_hidden_service() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010042, "com.example.hidden");
        
        // Hidden long-running service with background activity
        app.foreground_service_time_ms = 25_200_000; // 7 hours
        app.background_jobs.push(BackgroundJob {
            name: "background_task".to_string(),
            time_ms: 5000,
            count: 10,
        });
        app.total_job_count = 10;
        
        let indicators = detector.detect_backdoor(&app);
        
        assert!(!indicators.is_empty(), "Should detect backdoor hidden service");
        assert!(indicators[0].contains("Hidden persistent service"));
    }
    
    #[test]
    fn test_backdoor_package_update_monitoring() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010043, "com.example.updater");
        
        // Monitoring package updates
        app.background_jobs.push(BackgroundJob {
            name: "android.intent.action.PACKAGE_REPLACED".to_string(),
            time_ms: 3000,
            count: 4,
        });
        app.background_jobs.push(BackgroundJob {
            name: "android.intent.action.MY_PACKAGE_REPLACED".to_string(),
            time_ms: 2000,
            count: 3,
        });
        app.total_job_count = 7;
        
        let indicators = detector.detect_backdoor(&app);
        
        assert!(!indicators.is_empty(), "Should detect backdoor update monitoring");
        assert!(indicators[0].contains("Package update monitoring"));
    }
    
    #[test]
    fn test_backdoor_all_indicators() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010044, "com.example.fullbackdoor");
        
        // Boot receivers
        app.background_jobs.push(BackgroundJob {
            name: "BOOT_COMPLETED".to_string(),
            time_ms: 2000,
            count: 4,
        });
        
        // Hidden service
        app.foreground_service_time_ms = 28_800_000; // 8 hours
        app.background_jobs.push(BackgroundJob {
            name: "maintenance".to_string(),
            time_ms: 3000,
            count: 5,
        });
        
        // Update monitoring
        app.background_jobs.push(BackgroundJob {
            name: "PACKAGE_REPLACED".to_string(),
            time_ms: 2500,
            count: 6,
        });
        
        app.total_job_count = 15;
        
        let indicators = detector.detect_backdoor(&app);
        
        assert!(indicators.len() >= 3, "Should detect all backdoor indicators");
    }
    
    // ==================== PRIVILEGE ESCALATION TESTS ====================
    
    #[test]
    fn test_privesc_system_call_dominance() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010050, "com.example.privesc");
        
        // System CPU dominance
        app.cpu_user_time_ms = 15_000;
        app.cpu_system_time_ms = 60_000; // 4:1 ratio
        
        let indicators = detector.detect_privilege_escalation(&app);
        
        assert!(!indicators.is_empty(), "Should detect privilege escalation");
        assert!(indicators[0].contains("System call dominance"));
        assert!(indicators[0].contains("ratio 4.00:1"));
    }
    
    #[test]
    fn test_privesc_normal_ratio_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010051, "com.example.normal");
        
        // Normal ratio
        app.cpu_user_time_ms = 50_000;
        app.cpu_system_time_ms = 10_000;
        
        let indicators = detector.detect_privilege_escalation(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect with normal ratio");
    }
    
    #[test]
    fn test_privesc_root_access_attempts() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010052, "com.example.rooting");
        
        // Root-related jobs
        app.background_jobs.push(BackgroundJob {
            name: "su_request".to_string(),
            time_ms: 1000,
            count: 3,
        });
        app.background_jobs.push(BackgroundJob {
            name: "superuser_check".to_string(),
            time_ms: 800,
            count: 2,
        });
        app.background_jobs.push(BackgroundJob {
            name: "root_access".to_string(),
            time_ms: 600,
            count: 2,
        });
        app.total_job_count = 7;
        
        let indicators = detector.detect_privilege_escalation(&app);
        
        assert!(!indicators.is_empty(), "Should detect root access attempts");
        assert!(indicators[0].contains("Root access attempts"));
    }
    
    #[test]
    fn test_privesc_combined_indicators() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010053, "com.example.fullprivesc");
        
        // System call dominance
        app.cpu_user_time_ms = 12_000;
        app.cpu_system_time_ms = 50_000;
        
        // Root attempts
        app.background_jobs.push(BackgroundJob {
            name: "privilege_escalation".to_string(),
            time_ms: 2000,
            count: 4,
        });
        app.total_job_count = 4;
        
        let indicators = detector.detect_privilege_escalation(&app);
        
        assert!(indicators.len() >= 2, "Should detect both privilege escalation indicators");
    }
    
    // ==================== LATERAL MOVEMENT TESTS ====================
    
    #[test]
    fn test_lateral_ipc_abuse() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010060, "com.example.lateral");
        
        // Excessive IPC activity
        app.background_jobs.push(BackgroundJob {
            name: "bind_service_remote".to_string(),
            time_ms: 3000,
            count: 8,
        });
        app.background_jobs.push(BackgroundJob {
            name: "send_intent_broadcast".to_string(),
            time_ms: 2500,
            count: 7,
        });
        app.background_jobs.push(BackgroundJob {
            name: "ipc_call_handler".to_string(),
            time_ms: 2000,
            count: 10,
        });
        app.total_job_count = 25;
        
        let indicators = detector.detect_lateral_movement(&app);
        
        assert!(!indicators.is_empty(), "Should detect lateral movement IPC abuse");
        assert!(indicators[0].contains("IPC activity"));
        assert!(indicators[0].contains("25 total calls"));
    }
    
    #[test]
    fn test_lateral_normal_ipc_no_detection() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010061, "com.example.normal");
        
        // Normal amount of IPC
        app.background_jobs.push(BackgroundJob {
            name: "bind_service".to_string(),
            time_ms: 1000,
            count: 3,
        });
        app.total_job_count = 3;
        
        let indicators = detector.detect_lateral_movement(&app);
        
        assert!(indicators.is_empty(), "Should NOT detect with normal IPC");
    }
    
    #[test]
    fn test_lateral_content_provider_access() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010062, "com.example.provider");
        
        // Content provider access
        for i in 0..8 {
            app.background_jobs.push(BackgroundJob {
                name: format!("content_provider_query_{}", i),
                time_ms: 500,
                count: 2,
            });
        }
        app.total_job_count = 16;
        
        let indicators = detector.detect_lateral_movement(&app);
        
        assert!(!indicators.is_empty(), "Should detect content provider access");
        assert!(indicators[0].contains("Content provider access"));
    }
    
    #[test]
    fn test_lateral_combined_indicators() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010063, "com.example.fulllateral");
        
        // IPC abuse
        app.background_jobs.push(BackgroundJob {
            name: "bind_remote_service".to_string(),
            time_ms: 5000,
            count: 12,
        });
        app.background_jobs.push(BackgroundJob {
            name: "broadcast_intent".to_string(),
            time_ms: 3000,
            count: 10,
        });
        
        // Content provider
        for i in 0..6 {
            app.background_jobs.push(BackgroundJob {
                name: format!("provider_access_{}", i),
                time_ms: 400,
                count: 2,
            });
        }
        
        app.total_job_count = 34;
        
        let indicators = detector.detect_lateral_movement(&app);
        
        assert!(indicators.len() >= 2, "Should detect both lateral movement indicators");
    }
    
    // ==================== CLASSIFICATION TESTS ====================
    
    #[test]
    fn test_classification_rce() {
        let detector = ExploitationDetector::new();
        
        let indicators = vec![
            "RCE indicator: code execution detected".to_string(),
            "RCE indicator: process spawning".to_string(),
            "RCE indicator: abnormal CPU".to_string(),
        ];
        
        let classification = detector.classify_exploitation(&indicators);
        
        assert_eq!(classification, ExploitationType::RemoteCodeExecution);
    }
    
    #[test]
    fn test_classification_c2() {
        let detector = ExploitationDetector::new();
        
        let indicators = vec![
            "C2 indicator: beaconing detected".to_string(),
            "C2 indicator: regular callbacks".to_string(),
        ];
        
        let classification = detector.classify_exploitation(&indicators);
        
        assert_eq!(classification, ExploitationType::CommandAndControl);
    }
    
    #[test]
    fn test_classification_mixed_indicators() {
        let detector = ExploitationDetector::new();
        
        // RCE should win (highest priority - score 3)
        let indicators = vec![
            "RCE indicator: code execution".to_string(),
            "C2 indicator: beaconing".to_string(),
            "Exfiltration indicator: uploads".to_string(),
        ];
        
        let classification = detector.classify_exploitation(&indicators);
        
        assert_eq!(classification, ExploitationType::RemoteCodeExecution);
    }
    
    // ==================== SEVERITY TESTS ====================
    
    #[test]
    fn test_severity_critical_types() {
        let detector = ExploitationDetector::new();
        
        let indicators = vec!["test".to_string()];
        
        // RCE should be critical
        let severity = detector.calculate_severity(&indicators, &ExploitationType::RemoteCodeExecution);
        assert_eq!(severity, SeverityLevel::Critical);
        
        // RAT should be critical
        let severity = detector.calculate_severity(&indicators, &ExploitationType::RemoteAccessTrojan);
        assert_eq!(severity, SeverityLevel::Critical);
        
        // Backdoor should be critical
        let severity = detector.calculate_severity(&indicators, &ExploitationType::Backdoor);
        assert_eq!(severity, SeverityLevel::Critical);
    }
    
    #[test]
    fn test_severity_high_types() {
        let detector = ExploitationDetector::new();
        
        let indicators = vec!["test".to_string()];
        
        // C2 should be high
        let severity = detector.calculate_severity(&indicators, &ExploitationType::CommandAndControl);
        assert_eq!(severity, SeverityLevel::High);
        
        // Exfiltration should be high
        let severity = detector.calculate_severity(&indicators, &ExploitationType::DataExfiltration);
        assert_eq!(severity, SeverityLevel::High);
    }
    
    #[test]
    fn test_severity_increases_with_indicators() {
        let detector = ExploitationDetector::new();
        
        // Few indicators
        let few_indicators = vec!["test1".to_string()];
        let severity_few = detector.calculate_severity(&few_indicators, &ExploitationType::LateralMovement);
        
        // Many indicators (need 6+ to jump severity level: base 2 + (6/3) = 4)
        let many_indicators = vec![
            "test1".to_string(),
            "test2".to_string(),
            "test3".to_string(),
            "test4".to_string(),
            "test5".to_string(),
            "test6".to_string(),
        ];
        let severity_many = detector.calculate_severity(&many_indicators, &ExploitationType::LateralMovement);
        
        assert!(severity_many > severity_few, "More indicators should increase severity");
    }
    
    // ==================== CONFIDENCE TESTS ====================
    
    #[test]
    fn test_confidence_increases_with_indicators() {
        let detector = ExploitationDetector::new();
        
        let few_indicators = vec!["indicator".to_string()];
        let conf_few = detector.calculate_confidence(&few_indicators, &ExploitationType::Unknown);
        
        let many_indicators = vec!["ind1".to_string(), "ind2".to_string(), "ind3".to_string()];
        let conf_many = detector.calculate_confidence(&many_indicators, &ExploitationType::Unknown);
        
        assert!(conf_many > conf_few, "More indicators should increase confidence");
    }
    
    #[test]
    fn test_confidence_high_value_indicators() {
        let detector = ExploitationDetector::new();
        
        let normal_indicators = vec!["some indicator".to_string()];
        let conf_normal = detector.calculate_confidence(&normal_indicators, &ExploitationType::Unknown);
        
        let high_value_indicators = vec![
            "RCE indicator: code execution detected".to_string(),
        ];
        let conf_high = detector.calculate_confidence(&high_value_indicators, &ExploitationType::RemoteCodeExecution);
        
        assert!(conf_high > conf_normal, "High-value indicators should boost confidence");
    }
    
    #[test]
    fn test_confidence_capped_at_95() {
        let detector = ExploitationDetector::new();
        
        let many_indicators: Vec<String> = (0..20)
            .map(|i| format!("RCE indicator: high value indicator {}", i))
            .collect();
        
        let confidence = detector.calculate_confidence(&many_indicators, &ExploitationType::RemoteCodeExecution);
        
        assert!(confidence <= 0.95, "Confidence should be capped at 0.95");
    }
    
    // ==================== INTEGRATION TESTS ====================
    
    #[test]
    fn test_full_detection_pipeline_rce() {
        let detector = ExploitationDetector::new();
        let mut app = create_clean_app(1010100, "com.example.compromised");
        
        // Build a fully compromised app
        app.cpu_user_time_ms = 8_000;
        app.cpu_system_time_ms = 50_000; // RCE indicator
        
        app.background_jobs.push(BackgroundJob {
            name: "exec_native".to_string(),
            time_ms: 2000,
            count: 6,
        });
        app.background_jobs.push(BackgroundJob {
            name: "fork_process".to_string(),
            time_ms: 1500,
            count: 5,
        });
        app.total_job_count = 11;
        
        let result = detector.analyze_app(&app);
        
        assert!(result.is_some(), "Should detect exploitation");
        let indicator = result.unwrap();
        assert_eq!(indicator.exploitation_type, ExploitationType::RemoteCodeExecution);
        assert_eq!(indicator.severity, SeverityLevel::Critical);
        assert!(indicator.confidence > 0.5);
        assert!(!indicator.indicators.is_empty());
    }
    
    #[test]
    fn test_no_detection_clean_app() {
        let detector = ExploitationDetector::new();
        let app = create_clean_app(1010101, "com.example.clean");
        
        let result = detector.analyze_app(&app);
        
        assert!(result.is_none(), "Should NOT detect exploitation in clean app");
    }
    
    #[test]
    fn test_detect_multiple_apps() {
        let detector = ExploitationDetector::new();
        
        let mut app1 = create_clean_app(1010102, "com.example.clean");
        
        let mut app2 = create_clean_app(1010103, "com.example.exploited");
        app2.cpu_user_time_ms = 10_000;
        app2.cpu_system_time_ms = 60_000;
        
        let mut app3 = create_clean_app(1010104, "com.example.alsoexploited");
        app3.network_tx_mobile = 300_000_000;
        app3.network_rx_mobile = 30_000_000;
        
        let apps = vec![app1, app2, app3];
        let results = detector.detect_exploitation(&apps);
        
        assert_eq!(results.len(), 2, "Should detect 2 exploited apps out of 3");
    }
}