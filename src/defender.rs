use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, PartialEq)]
pub enum DefenderStatus {
    Clean,
    ThreatDetected(String),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct DefenderResult {
    pub path: String,
    pub status: DefenderStatus,
    pub raw_output: String,
}

pub struct DefenderScanner {
    cli_path: Option<String>,
}

impl DefenderScanner {
    pub fn new() -> Self {
        Self {
            cli_path: find_defender_cli(),
        }
    }

    pub fn is_available(&self) -> bool {
        self.cli_path.is_some()
    }

    pub fn get_cli_path(&self) -> Option<String> {
        self.cli_path.clone()
    }

    pub fn scan_file(&self, target_path: &str) -> DefenderResult {
        let cli = match &self.cli_path {
            Some(p) => p,
            None => {
                return DefenderResult {
                    path: target_path.to_string(),
                    status: DefenderStatus::Error("Windows Defender CLI (MpCmdRun.exe) tidak ditemukan di sistem.".to_string()),
                    raw_output: String::new(),
                };
            }
        };

        if !Path::new(target_path).exists() {
            return DefenderResult {
                path: target_path.to_string(),
                status: DefenderStatus::Error("Berkas tidak ditemukan atau hak akses terbatas.".to_string()),
                raw_output: String::new(),
            };
        }

        let output = Command::new(cli)
            .creation_flags(CREATE_NO_WINDOW)
            .args(&["-Scan", "-ScanType", "3", "-File", target_path])
            .output();

        match output {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let combined = format!("{}\n{}", stdout, stderr);

                // Exit codes for MpCmdRun:
                // 0: No threat found
                // 2: Threat found!
                // others: error
                let status = if code == 0 {
                    DefenderStatus::Clean
                } else if code == 2 || combined.to_lowercase().contains("threat") {
                    let threat_name = extract_threat_name(&combined).unwrap_or_else(|| "Ancaman Malware Terdeteksi".to_string());
                    DefenderStatus::ThreatDetected(threat_name)
                } else {
                    DefenderStatus::Error(format!("Kode keluar {}: {}", code, combined.trim()))
                };

                DefenderResult {
                    path: target_path.to_string(),
                    status,
                    raw_output: combined,
                }
            }
            Err(e) => DefenderResult {
                path: target_path.to_string(),
                status: DefenderStatus::Error(format!("Gagal mengeksekusi MpCmdRun: {e}")),
                raw_output: String::new(),
            },
        }
    }
}

pub fn find_defender_cli() -> Option<String> {
    // 1. Try Platform directories (newest update first)
    if let Ok(entries) = std::fs::read_dir("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform") {
        let mut dirs: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        dirs.sort_by_key(|e| e.file_name());
        dirs.reverse();
        for dir in dirs {
            let p = dir.path().join("MpCmdRun.exe");
            if p.exists() {
                return Some(p.to_string_lossy().to_string());
            }
        }
    }

    // 2. Try Program Files standard location
    let standard = PathBuf::from("C:\\Program Files\\Windows Defender\\MpCmdRun.exe");
    if standard.exists() {
        return Some(standard.to_string_lossy().to_string());
    }

    None
}

fn extract_threat_name(output: &str) -> Option<String> {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("threat") && (lower.contains("found") || lower.contains("name")) {
            return Some(line.trim().to_string());
        }
    }
    None
}
