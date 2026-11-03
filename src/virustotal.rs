use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    #[serde(default)]
    pub timeout: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub category: String,
    pub engine_name: String,
    pub result: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VtScanReport {
    pub target: String,
    pub target_type: String, // "file" or "ip"
    pub stats: AnalysisStats,
    pub top_detections: Vec<String>,
    pub permalink: String,
}

#[derive(Debug, Deserialize)]
struct VtResponse {
    data: Option<VtData>,
    error: Option<VtError>,
}

#[derive(Debug, Deserialize)]
struct VtData {
    attributes: Option<VtAttributes>,
    links: Option<VtLinks>,
}

#[derive(Debug, Deserialize)]
struct VtLinks {
    #[serde(rename = "self")]
    _self_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VtAttributes {
    last_analysis_stats: Option<AnalysisStats>,
    last_analysis_results: Option<HashMap<String, EngineResult>>,
    meaningful_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VtError {
    message: String,
    code: String,
}

pub struct VirusTotalClient {
    api_key: String,
    client: Client,
}

impl VirusTotalClient {
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { api_key, client }
    }

    pub fn set_api_key(&mut self, key: String) {
        self.api_key = key.trim().to_string();
    }

    pub fn has_api_key(&self) -> bool {
        !self.api_key.is_empty()
    }

    pub fn check_file_hash(&self, sha256: &str) -> Result<VtScanReport, String> {
        if self.api_key.is_empty() {
            return Err("VirusTotal API Key belum diisi. Masukkan API key di pengaturan.".to_string());
        }

        let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
        let resp = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .map_err(|e| format!("HTTP request error: {e}"))?;

        if resp.status() == 404 {
            return Err("Hash berkas belum pernah dilaporkan/dianalisis di VirusTotal (Clean / Unknown).".to_string());
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("VirusTotal API error ({status}): {body}"));
        }

        let vt_res: VtResponse = resp.json().map_err(|e| format!("Gagal mem-parsing respon VT: {e}"))?;

        if let Some(err) = vt_res.error {
            return Err(format!("VT Error [{}]: {}", err.code, err.message));
        }

        let data = vt_res.data.ok_or_else(|| "Tidak ada data dari VirusTotal".to_string())?;
        let attr = data.attributes.ok_or_else(|| "Tidak ada atribut hasil analisis".to_string())?;
        let stats = attr.last_analysis_stats.unwrap_or(AnalysisStats {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            timeout: 0,
        });

        let mut top_detections = Vec::new();
        if let Some(results) = attr.last_analysis_results {
            for (engine, res) in results {
                if res.category == "malicious" || res.category == "suspicious" {
                    let d = format!("{}: {}", engine, res.result.unwrap_or_else(|| "Detected".to_string()));
                    top_detections.push(d);
                }
            }
        }

        let permalink = format!("https://www.virustotal.com/gui/file/{}", sha256);

        Ok(VtScanReport {
            target: sha256.to_string(),
            target_type: "file".to_string(),
            stats,
            top_detections,
            permalink,
        })
    }

    pub fn check_ip_address(&self, ip: &str) -> Result<VtScanReport, String> {
        if self.api_key.is_empty() {
            return Err("VirusTotal API Key belum diisi. Masukkan API key di pengaturan.".to_string());
        }

        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
        let resp = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .map_err(|e| format!("HTTP request error: {e}"))?;

        if resp.status() == 404 {
            return Err("Alamat IP tidak ditemukan di basis data VirusTotal.".to_string());
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("VirusTotal API error ({status}): {body}"));
        }

        let vt_res: VtResponse = resp.json().map_err(|e| format!("Gagal mem-parsing respon VT: {e}"))?;

        if let Some(err) = vt_res.error {
            return Err(format!("VT Error [{}]: {}", err.code, err.message));
        }

        let data = vt_res.data.ok_or_else(|| "Tidak ada data dari VirusTotal".to_string())?;
        let attr = data.attributes.ok_or_else(|| "Tidak ada atribut hasil analisis".to_string())?;
        let stats = attr.last_analysis_stats.unwrap_or(AnalysisStats {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            timeout: 0,
        });

        let mut top_detections = Vec::new();
        if let Some(results) = attr.last_analysis_results {
            for (engine, res) in results {
                if res.category == "malicious" || res.category == "suspicious" {
                    let d = format!("{}: {}", engine, res.result.unwrap_or_else(|| "Malicious".to_string()));
                    top_detections.push(d);
                }
            }
        }

        let permalink = format!("https://www.virustotal.com/gui/ip-address/{}", ip);

        Ok(VtScanReport {
            target: ip.to_string(),
            target_type: "ip".to_string(),
            stats,
            top_detections,
            permalink,
        })
    }
}
