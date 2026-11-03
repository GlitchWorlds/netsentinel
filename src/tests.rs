#[cfg(test)]
mod tests {
    use crate::app::AppConfig;
    use crate::net::NetworkScanner;
    use crate::virustotal::AnalysisStats;

    #[test]
    fn test_app_config_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.auto_refresh, false); // Default derive gives false, load() sets true
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
        // On a running Windows system, there are always active sockets/ports
        assert!(!conns.is_empty(), "Should detect at least 1 network socket");
        
        let has_known_state = conns.iter().any(|c| c.state == "LISTEN" || c.state == "ESTABLISHED" || c.state == "UDP");
        assert!(has_known_state, "Should find at least one LISTEN, ESTABLISHED, or UDP socket");
    }
}
