#[cfg(test)]
mod tests {
    use crate::anomaly::{analyze_anomaly, RiskLevel};
    use crate::app::AppConfig;
    use crate::defender::DefenderScanner;
    use crate::net::NetworkScanner;
    use crate::virustotal::AnalysisStats;

    #[test]
    fn test_app_config_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.auto_refresh, false);
        assert_eq!(config.refresh_interval_secs, 0);
    }

    #[test]
    fn test_vt_stats_serialization() {
        let json = r#"{
            "malicious": 2,
            "suspicious": 1,
            "harmless": 65,
            "undetected": 10
        }"#;
        let stats: AnalysisStats = serde_json::from_str(json).expect("Failed to deserialize VT stats");
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
        let has_known_state = conns.iter().any(|c| c.state == "LISTEN" || c.state == "ESTABLISHED" || c.state == "UDP");
        assert!(has_known_state, "Harus menemukan minimal satu socket LISTEN, ESTABLISHED, atau UDP");
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
        assert!(def.is_available(), "Windows Defender CLI harus ditemukan di sistem");
    }
}
