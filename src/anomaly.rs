#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Warning,
    Danger,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyReport {
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
}

impl AnomalyReport {
    #[allow(dead_code)]
    pub fn safe() -> Self {
        Self {
            risk: RiskLevel::Safe,
            reasons: Vec::new(),
        }
    }
}

// Known LOLBins (Living Off The Land Binaries) that rarely should have direct outbound internet connections
const LOLBINS: &[&str] = &[
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "certutil.exe",
    "mshta.exe",
    "cscript.exe",
    "wscript.exe",
    "vbc.exe",
    "csc.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "installutil.exe",
    "msbuild.exe",
    "wmic.exe",
    "bash.exe",
    "scrcons.exe",
];

// Common ports associated with reverse shells, malware C2, mining, Tor, and IRC bots
const SUSPICIOUS_PORTS: &[u16] = &[
    1337, 31337, 4444, 5555, 6666, 6667, 8888, 9001, 9050, 3333, 7777, 9999, 14444, 44444,
];

pub fn analyze_anomaly(
    process_name: &str,
    process_path: Option<&str>,
    remote_ip: &str,
    remote_port: u16,
    state: &str,
) -> AnomalyReport {
    let mut reasons = Vec::new();
    let mut risk = RiskLevel::Safe;

    let proc_lower = process_name.to_lowercase();
    let is_public_ip = is_public_internet_ip(remote_ip);

    // 1. LOLBin Detection
    if LOLBINS.iter().any(|&bin| bin == proc_lower) {
        if is_public_ip && state == "ESTABLISHED" {
            risk = RiskLevel::Danger;
            reasons.push(format!(
                "🚨 LOLBin Aktif: {} membuat koneksi keluar ke IP publik ({}:{})",
                process_name, remote_ip, remote_port
            ));
        } else if is_public_ip {
            if risk < RiskLevel::Warning {
                risk = RiskLevel::Warning;
            }
            reasons.push(format!(
                "⚠️ LOLBin: {} terhubung ke IP publik ({})",
                process_name, remote_ip
            ));
        }
    }

    // 2. Suspicious Execution Path
    if let Some(path_str) = process_path {
        let path_lower = path_str.to_lowercase();

        // Masquerading check: svchost, csrss, lsass, explorer
        if proc_lower == "svchost.exe" && !path_lower.starts_with("c:\\windows\\system32") && !path_lower.starts_with("c:\\windows\\syswow64") {
            risk = RiskLevel::Danger;
            reasons.push(format!("🚨 Masquerade: svchost.exe berjalan di luar System32 ({})", path_str));
        }

        if proc_lower == "explorer.exe" && !path_lower.starts_with("c:\\windows") {
            risk = RiskLevel::Danger;
            reasons.push(format!("🚨 Masquerade: explorer.exe berjalan di luar C:\\Windows ({})", path_str));
        }

        // Running out of temp or user writable appdata
        if path_lower.contains("\\appdata\\local\\temp") || path_lower.contains("\\windows\\temp") {
            if is_public_ip {
                risk = RiskLevel::Danger;
                reasons.push("🚨 Eksekusi dari folder Temp dengan koneksi internet aktif".to_string());
            } else {
                if risk < RiskLevel::Warning {
                    risk = RiskLevel::Warning;
                }
                reasons.push("⚠️ Eksekusi aplikasi dari direktori Temp".to_string());
            }
        } else if path_lower.contains("\\appdata\\roaming") && !path_lower.contains("\\programs\\") {
            if is_public_ip {
                if risk < RiskLevel::Warning {
                    risk = RiskLevel::Warning;
                }
                reasons.push("⚠️ Aplikasi berjalan dari AppData\\Roaming".to_string());
            }
        } else if path_lower.contains("c:\\users\\public") {
            risk = RiskLevel::Danger;
            reasons.push("🚨 Aplikasi berjalan dari C:\\Users\\Public (sering digunakan trojan/stealer)".to_string());
        }
    }

    // 3. Suspicious Remote Port
    if is_public_ip && SUSPICIOUS_PORTS.contains(&remote_port) {
        if risk < RiskLevel::Warning {
            risk = RiskLevel::Warning;
        }
        reasons.push(format!("⚠️ Port remote mencurigakan (port {})", remote_port));
    }

    // 4. Abnormal non-executable or scripting process
    if proc_lower.ends_with(".vbs") || proc_lower.ends_with(".bat") || proc_lower.ends_with(".ps1") {
        risk = RiskLevel::Danger;
        reasons.push(format!("🚨 Eksekusi script langsung ({}) membuka socket", process_name));
    }

    AnomalyReport { risk, reasons }
}

fn is_public_internet_ip(ip: &str) -> bool {
    if ip.is_empty() || ip == "*" || ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "::" {
        return false;
    }

    // Private IPv4 ranges
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("169.254.") {
        return false;
    }

    if ip.starts_with("172.") {
        if let Some(second_octet) = ip.split('.').nth(1) {
            if let Ok(num) = second_octet.parse::<u8>() {
                if (16..=31).contains(&num) {
                    return false;
                }
            }
        }
    }

    // Multicast or broadcast
    if ip.starts_with("224.") || ip.starts_with("239.") || ip == "255.255.255.255" {
        return false;
    }

    // IPv6 link local or private
    if ip.to_lowercase().starts_with("fe80:") || ip.to_lowercase().starts_with("fc") || ip.to_lowercase().starts_with("fd") {
        return false;
    }

    true
}
