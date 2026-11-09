#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use crate::anomaly::{analyze_anomaly, RiskLevel};
    use crate::app::AppConfig;
    use crate::autostart::{
        disable_auto_start_custom, format_exe_command, get_auto_start_command_custom,
        get_current_exe_command, is_auto_start_enabled_custom, set_auto_start_custom,
    };
    use crate::defender::DefenderScanner;
    use crate::net::NetworkScanner;
    use crate::traffic::{
        bytes_to_mb, format_duration, format_session_mb, format_speed, is_loopback, TrafficTracker,
    };
    use crate::virustotal::AnalysisStats;

    #[test]
    fn test_app_config_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.auto_refresh, false);
        assert_eq!(config.refresh_interval_secs, 0);
        assert_eq!(config.auto_start, false);
    }

    #[test]
    fn test_vt_stats_serialization() {
        let json = r#"{
            "malicious": 2,
            "suspicious": 1,
            "harmless": 65,
            "undetected": 10
        }"#;
        let stats: AnalysisStats =
            serde_json::from_str(json).expect("Failed to deserialize VT stats");
        assert_eq!(stats.malicious, 2);
        assert_eq!(stats.suspicious, 1);
        assert_eq!(stats.harmless, 65);
        assert_eq!(stats.undetected, 10);
    }

    #[test]
    fn test_network_scanner_init() {
        let mut scanner = NetworkScanner::new();
        let conns = scanner.scan_connections();
        assert!(!conns.is_empty(), "Harus mendeteksi minimal 1 socket jaringan");
        let has_known_state = conns
            .iter()
            .any(|c| c.state == "LISTEN" || c.state == "ESTABLISHED" || c.state == "UDP");
        assert!(
            has_known_state,
            "Harus menemukan minimal satu socket LISTEN, ESTABLISHED, atau UDP"
        );
    }

    #[test]
    fn test_anomaly_detection_lolbin() {
        // powershell.exe connecting out to public IP is flagged as Danger
        let report = analyze_anomaly(
            "powershell.exe",
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            "185.220.101.5",
            4444,
            "ESTABLISHED",
        );
        assert_eq!(report.risk, RiskLevel::Danger);
        assert!(report.reasons.iter().any(|r| r.contains("LOLBin Aktif")));
        assert!(report.reasons.iter().any(|r| r.contains("Port remote mencurigakan")));
    }

    #[test]
    fn test_anomaly_detection_masquerade() {
        // svchost running outside System32
        let report = analyze_anomaly(
            "svchost.exe",
            Some("C:\\Users\\Bob\\AppData\\Local\\Temp\\svchost.exe"),
            "1.2.3.4",
            80,
            "ESTABLISHED",
        );
        assert_eq!(report.risk, RiskLevel::Danger);
        assert!(report.reasons.iter().any(|r| r.contains("Masquerade")));
    }

    #[test]
    fn test_defender_scanner_availability() {
        let def = DefenderScanner::new();
        // On standard Windows 10/11 system, Defender is present
        assert!(
            def.is_available(),
            "Windows Defender CLI harus ditemukan di sistem"
        );
    }

    #[test]
    fn test_traffic_formatting() {
        // Speed formatting
        assert_eq!(format_speed(0.0), "0 B/s");
        assert_eq!(format_speed(-10.0), "0 B/s");
        assert_eq!(format_speed(512.0), "512 B/s");
        assert_eq!(format_speed(1024.0), "1.0 KB/s");
        assert_eq!(format_speed(1536.0), "1.5 KB/s");
        assert_eq!(format_speed(1024.0 * 1024.0), "1.00 MB/s");
        assert_eq!(format_speed(1024.0 * 1024.0 * 2.5), "2.50 MB/s");
        assert_eq!(format_speed(1024.0 * 1024.0 * 1024.0 * 1.25), "1.25 GB/s");

        // Bytes to MB
        assert_eq!(bytes_to_mb(0), 0.0);
        assert_eq!(bytes_to_mb(1024 * 1024), 1.0);
        assert_eq!(bytes_to_mb(1024 * 1024 * 50), 50.0);

        // Session MB formatting
        assert_eq!(format_session_mb(0), "0.00 MB");
        assert_eq!(format_session_mb(524_288), "0.50 MB");
        assert_eq!(format_session_mb(1024 * 1024 * 12), "12.00 MB");
        // >= 1 GB displays both MB and GB
        let one_and_half_gb = (1024 * 1024 * 1024) + (512 * 1024 * 1024);
        let formatted_gb = format_session_mb(one_and_half_gb);
        assert!(
            formatted_gb.contains("1536.00 MB"),
            "Harus menampilkan MB: {formatted_gb}"
        );
        assert!(
            formatted_gb.contains("1.50 GB"),
            "Harus menampilkan GB saat >= 1024 MB: {formatted_gb}"
        );

        // Duration formatting
        assert_eq!(format_duration(Duration::from_secs(5)), "00:05");
        assert_eq!(format_duration(Duration::from_secs(65)), "01:05");
        assert_eq!(format_duration(Duration::from_secs(3665)), "01:01:05");
    }

    #[test]
    fn test_traffic_loopback_filtering() {
        assert!(is_loopback("Loopback Pseudo-Interface 1"));
        assert!(is_loopback("loopback"));
        assert!(is_loopback("lo"));
        assert!(is_loopback("lo0"));
        assert!(!is_loopback("Wi-Fi"));
        assert!(!is_loopback("Ethernet"));
        assert!(!is_loopback("vEthernet (Default Switch)"));
    }

    #[test]
    fn test_traffic_tracker_session_lifecycle() {
        let mut tracker = TrafficTracker::new();
        assert_eq!(tracker.session_rx_bytes(), 0);
        assert_eq!(tracker.session_tx_bytes(), 0);
        assert_eq!(tracker.total_session_bytes(), 0);

        // First sample
        tracker.refresh();
        assert!(tracker.rx_rate_bps() >= 0.0);
        assert!(tracker.tx_rate_bps() >= 0.0);

        // Reset session
        tracker.reset_session();
        assert_eq!(tracker.session_rx_bytes(), 0);
        assert_eq!(tracker.session_tx_bytes(), 0);
        assert_eq!(tracker.total_session_bytes(), 0);
    }

    #[test]
    fn test_autostart_command_formatting() {
        let path = Path::new("C:\\Program Files\\NetSentinel\\netsentinel.exe");
        let cmd = format_exe_command(path);
        assert_eq!(cmd, "\"C:\\Program Files\\NetSentinel\\netsentinel.exe\"");

        // Check current exe command
        let curr = get_current_exe_command();
        assert!(curr.is_ok());
        let cmd_str = curr.unwrap();
        assert!(cmd_str.starts_with('"') && cmd_str.ends_with('"'));
        assert!(cmd_str.to_lowercase().contains("netsentinel"));
    }

    #[test]
    fn test_autostart_registry_custom_key() {
        let test_name = "NetSentinel_UnitTest_Temp";
        let test_cmd = "\"C:\\Program Files\\NetSentinel\\netsentinel.exe\"";

        // Ensure clean initial state for test key
        let _ = disable_auto_start_custom(test_name);
        assert!(!is_auto_start_enabled_custom(test_name));

        // Enable custom key
        let res = set_auto_start_custom(test_name, test_cmd);
        assert!(res.is_ok(), "Setting custom auto-start key must succeed");

        // Verify key is enabled
        assert!(is_auto_start_enabled_custom(test_name));

        // Verify command matches
        let read_cmd = get_auto_start_command_custom(test_name);
        assert_eq!(read_cmd.as_deref(), Some(test_cmd));

        // Disable custom key
        let del_res = disable_auto_start_custom(test_name);
        assert!(del_res.is_ok(), "Deleting custom auto-start key must succeed");

        // Verify key is no longer enabled
        assert!(!is_auto_start_enabled_custom(test_name));

        // Deleting already deleted key should be idempotent (no error)
        let del_again = disable_auto_start_custom(test_name);
        assert!(del_again.is_ok(), "Idempotent delete must succeed");
    }
}
