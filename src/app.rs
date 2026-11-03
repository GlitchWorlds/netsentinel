use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};

use crate::anomaly::RiskLevel;
use crate::defender::{DefenderResult, DefenderScanner, DefenderStatus};
use crate::net::{ConnectionInfo, NetworkScanner, Protocol};
use crate::virustotal::{VirusTotalClient, VtScanReport};

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct AppConfig {
    pub vt_api_key: String,
    pub auto_refresh: bool,
    pub refresh_interval_secs: u64,
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let p = PathBuf::from(appdata).join("NetSentinel");
            let _ = fs::create_dir_all(&p);
            p.join("config.json")
        } else {
            PathBuf::from("config.json")
        }
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if let Ok(content) = fs::read_to_string(path) {
            serde_json::from_str(&content).unwrap_or_else(|_| Self {
                vt_api_key: String::new(),
                auto_refresh: true,
                refresh_interval_secs: 3,
            })
        } else {
            Self {
                vt_api_key: String::new(),
                auto_refresh: true,
                refresh_interval_secs: 3,
            }
        }
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, content);
        }
    }
}

enum VtWorkerResult {
    Success(VtScanReport),
    Error(String),
}

enum DefenderBatchMsg {
    Progress { current: usize, total: usize, result: DefenderResult },
    FinishedAll,
}

enum AppAction {
    ScanFileVt(String, String),
    ScanIpVt(String),
    ScanFileDefender(String),
    ScanAllDefender,
}

pub struct NetSentinelApp {
    scanner: NetworkScanner,
    defender: DefenderScanner,
    connections: Vec<ConnectionInfo>,
    search_query: String,
    filter_protocol: Option<Protocol>,
    filter_established_only: bool,
    filter_anomalies_only: bool,

    config: AppConfig,
    show_settings: bool,
    api_key_input: String,

    last_refresh: Instant,
    status_text: String,

    selected_conn: Option<ConnectionInfo>,
    vt_client: VirusTotalClient,

    // VirusTotal Background State
    is_scanning_vt: bool,
    active_scan_target: String,
    vt_report: Option<VtScanReport>,
    vt_error: Option<String>,
    vt_rx: Option<Receiver<VtWorkerResult>>,

    // Windows Defender State
    defender_cache: HashMap<String, DefenderResult>,
    is_scanning_defender_single: bool,
    active_defender_target: String,
    single_defender_rx: Option<Receiver<DefenderResult>>,

    // Defender Batch Scan All State
    is_scanning_all_defender: bool,
    scan_all_progress: (usize, usize),
    batch_defender_rx: Option<Receiver<DefenderBatchMsg>>,
}

impl NetSentinelApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut scanner = NetworkScanner::new();
        let connections = scanner.scan_connections();
        let defender = DefenderScanner::new();
        let config = AppConfig::load();
        let vt_client = VirusTotalClient::new(config.vt_api_key.clone());
        let api_key_input = config.vt_api_key.clone();

        Self {
            scanner,
            defender,
            connections,
            search_query: String::new(),
            filter_protocol: None,
            filter_established_only: false,
            filter_anomalies_only: false,
            config,
            show_settings: false,
            api_key_input,
            last_refresh: Instant::now(),
            status_text: "NetSentinel siap. Memindai koneksi jaringan & analisis anomali.".to_string(),
            selected_conn: None,
            vt_client,
            is_scanning_vt: false,
            active_scan_target: String::new(),
            vt_report: None,
            vt_error: None,
            vt_rx: None,
            defender_cache: HashMap::new(),
            is_scanning_defender_single: false,
            active_defender_target: String::new(),
            single_defender_rx: None,
            is_scanning_all_defender: false,
            scan_all_progress: (0, 0),
            batch_defender_rx: None,
        }
    }

    pub fn refresh_network(&mut self) {
        self.connections = self.scanner.scan_connections();
        self.last_refresh = Instant::now();
        let anomaly_count = self.connections.iter().filter(|c| c.anomaly.risk != RiskLevel::Safe).count();
        self.status_text = format!(
            "Pembaruan selesai: {} koneksi aktif ({} terdeteksi anomali/perhatian).",
            self.connections.len(),
            anomaly_count
        );
    }

    fn check_background_tasks(&mut self) {
        // 1. VirusTotal receiver
        if let Some(ref rx) = self.vt_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_scanning_vt = false;
                match result {
                    VtWorkerResult::Success(report) => {
                        self.vt_report = Some(report);
                        self.vt_error = None;
                        self.status_text = format!("Pemeriksaan VirusTotal berhasil untuk {}", self.active_scan_target);
                    }
                    VtWorkerResult::Error(err) => {
                        self.vt_error = Some(err.clone());
                        self.vt_report = None;
                        self.status_text = format!("Pemeriksaan VirusTotal gagal: {}", err);
                    }
                }
                self.vt_rx = None;
            }
        }

        // 2. Single Defender receiver
        if let Some(ref rx) = self.single_defender_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_scanning_defender_single = false;
                self.status_text = match &result.status {
                    DefenderStatus::Clean => format!("Defender: {} dinyatakan BERSIH.", self.active_defender_target),
                    DefenderStatus::ThreatDetected(threat) => format!("🚨 DEFENDER ALERT: {} pada {}!", threat, self.active_defender_target),
                    DefenderStatus::Error(e) => format!("Defender error: {}", e),
                };
                self.defender_cache.insert(result.path.clone(), result);
                self.single_defender_rx = None;
            }
        }

        // 3. Batch Scan All Defender receiver
        if let Some(ref rx) = self.batch_defender_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    DefenderBatchMsg::Progress { current, total, result } => {
                        self.scan_all_progress = (current, total);
                        if let DefenderStatus::ThreatDetected(ref threat) = result.status {
                            self.status_text = format!("🚨 DETEKSI ANCAMAN DEFENDER: {} pada {}", threat, result.path);
                        } else {
                            self.status_text = format!("Memindai seluruh proses dengan Defender... ({}/{})", current, total);
                        }
                        self.defender_cache.insert(result.path.clone(), result);
                    }
                    DefenderBatchMsg::FinishedAll => {
                        self.is_scanning_all_defender = false;
                        self.status_text = format!(
                            "Pemindaian seluruh proses selesai. {} berkas executable telah diperiksa.",
                            self.scan_all_progress.1
                        );
                        self.batch_defender_rx = None;
                        break;
                    }
                }
            }
        }
    }

    fn trigger_scan_file_vt(&mut self, sha256: String, file_name: String) {
        if !self.vt_client.has_api_key() {
            self.vt_error = Some("VirusTotal API Key belum diisi. Buka Pengaturan untuk memasukkan API Key.".to_string());
            self.show_settings = true;
            return;
        }

        self.is_scanning_vt = true;
        self.active_scan_target = format!("Berkas: {} ({})", file_name, &sha256[..8.min(sha256.len())]);
        self.vt_report = None;
        self.vt_error = None;

        let (tx, rx): (Sender<VtWorkerResult>, Receiver<VtWorkerResult>) = channel();
        self.vt_rx = Some(rx);

        let vt_token = self.config.vt_api_key.clone();
        thread::spawn(move || {
            let client = VirusTotalClient::new(vt_token);
            match client.check_file_hash(&sha256) {
                Ok(report) => {
                    let _ = tx.send(VtWorkerResult::Success(report));
                }
                Err(e) => {
                    let _ = tx.send(VtWorkerResult::Error(e));
                }
            }
        });
    }

    fn trigger_scan_ip_vt(&mut self, ip: String) {
        if !self.vt_client.has_api_key() {
            self.vt_error = Some("VirusTotal API Key belum diisi. Buka Pengaturan untuk memasukkan API Key.".to_string());
            self.show_settings = true;
            return;
        }

        if ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "*" || ip.is_empty() {
            self.vt_error = Some(format!("Alamat IP '{}' adalah IP lokal/wildcard dan tidak relevan untuk VirusTotal.", ip));
            return;
        }

        self.is_scanning_vt = true;
        self.active_scan_target = format!("IP Publik: {}", ip);
        self.vt_report = None;
        self.vt_error = None;

        let (tx, rx): (Sender<VtWorkerResult>, Receiver<VtWorkerResult>) = channel();
        self.vt_rx = Some(rx);

        let vt_token = self.config.vt_api_key.clone();
        thread::spawn(move || {
            let client = VirusTotalClient::new(vt_token);
            match client.check_ip_address(&ip) {
                Ok(report) => {
                    let _ = tx.send(VtWorkerResult::Success(report));
                }
                Err(e) => {
                    let _ = tx.send(VtWorkerResult::Error(e));
                }
            }
        });
    }

    fn trigger_scan_file_defender(&mut self, target_path: String) {
        self.is_scanning_defender_single = true;
        self.active_defender_target = target_path.clone();

        let (tx, rx): (Sender<DefenderResult>, Receiver<DefenderResult>) = channel();
        self.single_defender_rx = Some(rx);

        thread::spawn(move || {
            let scanner = DefenderScanner::new();
            let res = scanner.scan_file(&target_path);
            let _ = tx.send(res);
        });
    }

    fn trigger_scan_all_defender(&mut self) {
        // Collect all distinct executable paths currently active
        let mut paths: Vec<String> = self
            .connections
            .iter()
            .filter_map(|c| c.process_path.clone())
            .collect();
        paths.sort();
        paths.dedup();

        if paths.is_empty() {
            self.status_text = "Tidak ada path executable yang dapat dipindai.".to_string();
            return;
        }

        let total = paths.len();
        self.is_scanning_all_defender = true;
        self.scan_all_progress = (0, total);
        self.status_text = format!("Memulai pemindaian Windows Defender untuk {} berkas proses...", total);

        let (tx, rx): (Sender<DefenderBatchMsg>, Receiver<DefenderBatchMsg>) = channel();
        self.batch_defender_rx = Some(rx);

        thread::spawn(move || {
            let scanner = DefenderScanner::new();
            for (idx, p) in paths.into_iter().enumerate() {
                let res = scanner.scan_file(&p);
                let _ = tx.send(DefenderBatchMsg::Progress {
                    current: idx + 1,
                    total,
                    result: res,
                });
            }
            let _ = tx.send(DefenderBatchMsg::FinishedAll);
        });
    }
}

impl eframe::App for NetSentinelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_background_tasks();

        // Auto refresh tick
        if self.config.auto_refresh
            && self.last_refresh.elapsed() >= Duration::from_secs(self.config.refresh_interval_secs)
            && !self.is_scanning_vt
            && !self.is_scanning_all_defender
        {
            self.refresh_network();
        }

        // Request repaint if scanning
        if self.is_scanning_vt || self.is_scanning_all_defender || self.is_scanning_defender_single {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        let mut app_action: Option<AppAction> = None;

        // Top Panel: Header & Controls
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("🛡️ NetSentinel").size(20.0).strong().color(Color32::from_rgb(0, 215, 255)));
                ui.label(RichText::new("v2.1.0 | Real-time Network Anomaly Monitor, Defender Engine & VirusTotal").color(Color32::GRAY));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙️ Pengaturan").clicked() {
                        self.show_settings = !self.show_settings;
                    }

                    if self.is_scanning_all_defender {
                        let (cur, tot) = self.scan_all_progress;
                        ui.label(RichText::new(format!("⏳ Pindai Defender ({}/{})", cur, tot)).color(Color32::GOLD).strong());
                    } else {
                        if ui.button("🛡️ Scan All (Defender Gratis)").clicked() {
                            app_action = Some(AppAction::ScanAllDefender);
                        }
                    }

                    if ui.button("🔄 Segarkan").clicked() {
                        self.refresh_network();
                    }

                    let auto_label = if self.config.auto_refresh { "🟢 Auto (3s)" } else { "⚪ Auto Off" };
                    if ui.selectable_label(self.config.auto_refresh, auto_label).clicked() {
                        self.config.auto_refresh = !self.config.auto_refresh;
                        self.config.save();
                    }
                });
            });

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            // Filter bar
            ui.horizontal(|ui| {
                ui.label("🔍 Cari:");
                ui.add(egui::TextEdit::singleline(&mut self.search_query).hint_text("Nama proses, PID, IP, port...").desired_width(200.0));

                ui.separator();
                ui.label("Protokol:");
                if ui.selectable_label(self.filter_protocol.is_none(), "Semua").clicked() {
                    self.filter_protocol = None;
                }
                if ui.selectable_label(self.filter_protocol == Some(Protocol::Tcp), "TCP").clicked() {
                    self.filter_protocol = Some(Protocol::Tcp);
                }
                if ui.selectable_label(self.filter_protocol == Some(Protocol::Udp), "UDP").clicked() {
                    self.filter_protocol = Some(Protocol::Udp);
                }

                ui.separator();
                ui.checkbox(&mut self.filter_established_only, "ESTABLISHED saja");

                ui.separator();
                let anomaly_toggle_label = if self.filter_anomalies_only {
                    RichText::new("⚠️ Hanya Anomali / Mencurigakan").color(Color32::from_rgb(255, 100, 100)).strong()
                } else {
                    RichText::new("⚠️ Hanya Anomali").color(Color32::LIGHT_GRAY)
                };
                ui.checkbox(&mut self.filter_anomalies_only, anomaly_toggle_label);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let total_conns = self.connections.len();
                    let danger_count = self.connections.iter().filter(|c| c.anomaly.risk == RiskLevel::Danger).count();
                    let warn_count = self.connections.iter().filter(|c| c.anomaly.risk == RiskLevel::Warning).count();

                    let stats_text = if danger_count > 0 {
                        RichText::new(format!("Total: {} (🚨 {} Bahaya, ⚠️ {} Waspada)", total_conns, danger_count, warn_count)).color(Color32::from_rgb(255, 100, 100)).strong()
                    } else if warn_count > 0 {
                        RichText::new(format!("Total: {} (⚠️ {} Waspada)", total_conns, warn_count)).color(Color32::GOLD)
                    } else {
                        RichText::new(format!("Total: {} koneksi", total_conns)).color(Color32::LIGHT_GRAY)
                    };
                    ui.label(stats_text);
                });
            });
            ui.add_space(6.0);
        });

        // Bottom status bar
        egui::TopBottomPanel::bottom("bottom_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status_text).size(12.0).color(Color32::LIGHT_GRAY));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let def_status = if self.defender.is_available() {
                        RichText::new("Defender: Tersedia (Lokal)").color(Color32::GREEN)
                    } else {
                        RichText::new("Defender: Tidak Ditemukan").color(Color32::GRAY)
                    };
                    ui.label(def_status);

                    ui.separator();

                    let vt_status = if self.vt_client.has_api_key() {
                        RichText::new("VT API: Terhubung").color(Color32::GREEN)
                    } else {
                        RichText::new("VT API: Belum Ada Key").color(Color32::GOLD)
                    };
                    ui.label(vt_status);
                });
            });
        });

        // Settings Dialog Window
        if self.show_settings {
            egui::Window::new("⚙️ Pengaturan NetSentinel")
                .collapsible(false)
                .resizable(false)
                .default_size(Vec2::new(450.0, 240.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.heading("Konfigurasi Mesin Pemindai");
                    ui.label("NetSentinel menggabungkan mesin Windows Defender (100% lokal & gratis) dan VirusTotal API (intelijen cloud).");

                    ui.add_space(8.0);
                    ui.label("VirusTotal API Key:");
                    ui.add(egui::TextEdit::singleline(&mut self.api_key_input).password(true).desired_width(400.0));

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Interval Auto Refresh (detik):");
                        let mut interval = self.config.refresh_interval_secs;
                        if ui.add(egui::Slider::new(&mut interval, 1..=30).suffix(" s")).changed() {
                            self.config.refresh_interval_secs = interval;
                        }
                    });

                    ui.add_space(6.0);
                    ui.label(format!("Path Defender CLI: {}", self.defender.get_cli_path().unwrap_or_else(|| "Tidak ditemukan".to_string())));

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);

                    ui.horizontal(|ui| {
                        if ui.button("💾 Simpan").clicked() {
                            self.config.vt_api_key = self.api_key_input.trim().to_string();
                            self.vt_client.set_api_key(self.config.vt_api_key.clone());
                            self.config.save();
                            self.show_settings = false;
                            self.status_text = "Pengaturan berhasil disimpan.".to_string();
                        }
                        if ui.button("Batal").clicked() {
                            self.api_key_input = self.config.vt_api_key.clone();
                            self.show_settings = false;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.link("Dapatkan VT API Key Gratis").clicked() {
                                let _ = webbrowser::open("https://www.virustotal.com/gui/my-apikey");
                            }
                        });
                    });
                });
        }

        // Side panel: Inspection, Anomaly & Antivirus Scanning
        egui::SidePanel::right("side_inspector")
            .min_width(340.0)
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading(RichText::new("🔬 Inspeksi & Keamanan").size(16.0).strong());
                ui.separator();

                if let Some(ref conn) = self.selected_conn {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Aplikasi:").strong());
                        ui.label(RichText::new(&conn.process_name).color(Color32::from_rgb(0, 210, 255)).strong());
                    });
                    ui.label(format!("PID: {}", conn.pid));
                    ui.label(format!("Protokol: {:?} | Status: {}", conn.protocol, conn.state));
                    ui.label(format!("Lokal: {}", conn.local_addr));
                    ui.label(format!("Remote: {}", conn.remote_addr));

                    ui.add_space(4.0);
                    ui.label(RichText::new("Path Executable:").strong());
                    if let Some(ref path) = conn.process_path {
                        ui.monospace(path);
                        ui.horizontal(|ui| {
                            if ui.button("📁 Buka Lokasi").clicked() {
                                if let Some(parent) = PathBuf::from(path).parent() {
                                    let _ = webbrowser::open(&parent.to_string_lossy());
                                }
                            }
                        });
                    } else {
                        ui.label(RichText::new("Tidak dapat diakses / hak akses terbatas").color(Color32::GRAY));
                    }

                    // Anomaly Heuristics Box
                    ui.add_space(8.0);
                    ui.separator();
                    ui.heading(RichText::new("🚨 Analisis Anomali Jaringan").size(14.0));
                    match conn.anomaly.risk {
                        RiskLevel::Danger => {
                            ui.label(RichText::new("Status: BAHAYA TINGGI (Anomali Kritis)").color(Color32::from_rgb(255, 75, 75)).strong());
                        }
                        RiskLevel::Warning => {
                            ui.label(RichText::new("Status: WASPADA (Perilaku Tidak Lazim)").color(Color32::GOLD).strong());
                        }
                        RiskLevel::Safe => {
                            ui.label(RichText::new("Status: Normal (Tidak ada anomali terdeteksi)").color(Color32::from_rgb(50, 205, 50)));
                        }
                    }

                    if !conn.anomaly.reasons.is_empty() {
                        ui.group(|ui| {
                            for r in &conn.anomaly.reasons {
                                ui.label(RichText::new(format!("• {}", r)).size(11.5).color(Color32::from_rgb(255, 140, 140)));
                            }
                        });
                    }

                    // Windows Defender Section (100% Free & Local)
                    ui.add_space(8.0);
                    ui.separator();
                    ui.heading(RichText::new("🛡️ Windows Defender (Lokal - Gratis)").size(14.0));

                    if let Some(ref path) = conn.process_path {
                        if self.is_scanning_defender_single && self.active_defender_target == *path {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("Memindai berkas dengan Microsoft Defender...");
                            });
                        } else {
                            if ui.button("🛡️ Pindai Berkas dengan Defender").clicked() {
                                app_action = Some(AppAction::ScanFileDefender(path.clone()));
                            }
                        }

                        // Check if in cache
                        if let Some(def_res) = self.defender_cache.get(path) {
                            ui.group(|ui| {
                                match &def_res.status {
                                    DefenderStatus::Clean => {
                                        ui.label(RichText::new("✅ DEFENDER: Berkas dinyatakan BERSIH.").color(Color32::from_rgb(50, 205, 50)).strong());
                                    }
                                    DefenderStatus::ThreatDetected(threat) => {
                                        ui.label(RichText::new(format!("🚨 ANCAMAN DEFENDER: {}", threat)).color(Color32::from_rgb(255, 75, 75)).strong());
                                    }
                                    DefenderStatus::Error(e) => {
                                        ui.label(RichText::new(format!("⚠️ Defender Catatan: {}", e)).color(Color32::GOLD));
                                    }
                                }
                            });
                        }
                    } else {
                        ui.label(RichText::new("Tidak ada berkas yang dapat dipindai").color(Color32::GRAY));
                    }

                    // VirusTotal Section
                    ui.add_space(8.0);
                    ui.separator();
                    ui.heading(RichText::new("🌐 VirusTotal (Cloud Threat Intel)").size(14.0));

                    if self.is_scanning_vt {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(format!("Memeriksa {}...", self.active_scan_target));
                        });
                    } else {
                        if let Some(ref path) = conn.process_path {
                            let mut scanner = NetworkScanner::new();
                            if let Some(hash) = scanner.get_file_sha256(path) {
                                ui.label(RichText::new("SHA256 Executable:").size(11.0).color(Color32::GRAY));
                                ui.monospace(format!("{}...", &hash[..16.min(hash.len())]));

                                if ui.button("🔍 Cek Berkas di VirusTotal").clicked() {
                                    app_action = Some(AppAction::ScanFileVt(hash, conn.process_name.clone()));
                                }
                            }
                        }

                        if conn.remote_ip != "*" && conn.remote_ip != "0.0.0.0" && conn.remote_ip != "127.0.0.1" && conn.remote_ip != "::1" && !conn.remote_ip.is_empty() {
                            let ip = conn.remote_ip.clone();
                            if ui.button(format!("🌐 Cek IP {} di VirusTotal", ip)).clicked() {
                                app_action = Some(AppAction::ScanIpVt(ip));
                            }
                        }
                    }

                    // Display VT Report
                    if let Some(ref err) = self.vt_error {
                        ui.add_space(4.0);
                        ui.group(|ui| {
                            ui.label(RichText::new("⚠️ Catatan / Peringatan:").color(Color32::GOLD).strong());
                            ui.label(err);
                        });
                    }

                    if let Some(ref report) = self.vt_report {
                        ui.add_space(4.0);
                        ui.group(|ui| {
                            ui.label(RichText::new("📊 Hasil Analisis VirusTotal").strong().color(Color32::WHITE));
                            ui.label(format!("Target: {}", report.target));

                            let mal = report.stats.malicious;
                            let susp = report.stats.suspicious;
                            let harmless = report.stats.harmless;
                            let undet = report.stats.undetected;

                            let score_color = if mal > 0 {
                                Color32::from_rgb(255, 75, 75)
                            } else if susp > 0 {
                                Color32::GOLD
                            } else {
                                Color32::from_rgb(50, 205, 50)
                            };

                            ui.horizontal(|ui| {
                                ui.label("Skor Deteksi:");
                                ui.label(RichText::new(format!("{}/{} mesin", mal + susp, mal + susp + harmless + undet)).color(score_color).strong());
                            });

                            if mal > 0 {
                                ui.label(RichText::new("🚨 PERINGATAN: Terdeteksi Berbahaya!").color(Color32::from_rgb(255, 75, 75)).strong());
                            } else {
                                ui.label(RichText::new("✅ Tidak terdeteksi ancaman").color(Color32::from_rgb(50, 205, 50)));
                            }

                            if !report.top_detections.is_empty() {
                                ui.add_space(4.0);
                                ui.label(RichText::new("Deteksi Mesin AV:").strong());
                                for det in report.top_detections.iter().take(4) {
                                    ui.label(RichText::new(format!("• {}", det)).size(11.0).color(Color32::from_rgb(255, 120, 120)));
                                }
                            }

                            ui.add_space(4.0);
                            let permalink = report.permalink.clone();
                            if ui.button("🌐 Buka Laporan Lengkap di Web").clicked() {
                                let _ = webbrowser::open(&permalink);
                            }
                        });
                    }
                } else {
                    ui.add_space(20.0);
                    ui.label("Pilih salah satu koneksi dari tabel di sebelah kiri untuk melihat rincian proses, analisis anomali, pemindaian Defender gratis, atau pengecekan VirusTotal.");
                }
            });

        // Central Panel: Connection Table with Risk/Anomaly Indicator
        egui::CentralPanel::default().show(ctx, |ui| {
            let q = self.search_query.to_lowercase();
            let filtered: Vec<&ConnectionInfo> = self
                .connections
                .iter()
                .filter(|c| {
                    if let Some(proto) = &self.filter_protocol {
                        if &c.protocol != proto {
                            return false;
                        }
                    }
                    if self.filter_established_only && c.state != "ESTABLISHED" {
                        return false;
                    }
                    if self.filter_anomalies_only && c.anomaly.risk == RiskLevel::Safe {
                        return false;
                    }
                    if q.is_empty() {
                        return true;
                    }
                    c.process_name.to_lowercase().contains(&q)
                        || c.pid.to_string().contains(&q)
                        || c.local_addr.to_lowercase().contains(&q)
                        || c.remote_addr.to_lowercase().contains(&q)
                        || c.state.to_lowercase().contains(&q)
                })
                .collect();

            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new("conn_table")
                    .striped(true)
                    .min_col_width(70.0)
                    .show(ui, |ui| {
                        // Header
                        ui.label(RichText::new("Risiko / Anomali").strong());
                        ui.label(RichText::new("Aplikasi").strong());
                        ui.label(RichText::new("PID").strong());
                        ui.label(RichText::new("Protokol").strong());
                        ui.label(RichText::new("Alamat Lokal").strong());
                        ui.label(RichText::new("Alamat Remote").strong());
                        ui.label(RichText::new("Status").strong());
                        ui.label(RichText::new("Aksi").strong());
                        ui.end_row();

                        // Rows
                        for conn in filtered {
                            let is_selected = self.selected_conn.as_ref().map(|s| s.id == conn.id).unwrap_or(false);

                            // Check if defender flagged this path as threat
                            let is_defender_threat = conn.process_path.as_ref()
                                .and_then(|p| self.defender_cache.get(p))
                                .map(|r| matches!(r.status, DefenderStatus::ThreatDetected(_)))
                                .unwrap_or(false);

                            // Risk indicator badge
                            if is_defender_threat || conn.anomaly.risk == RiskLevel::Danger {
                                ui.label(RichText::new("🚨 BAHAYA").color(Color32::from_rgb(255, 75, 75)).strong());
                            } else if conn.anomaly.risk == RiskLevel::Warning {
                                ui.label(RichText::new("⚠️ WASPADA").color(Color32::GOLD).strong());
                            } else {
                                ui.label(RichText::new("✅ Normal").color(Color32::from_rgb(100, 190, 100)));
                            }

                            let name_label = if is_selected {
                                RichText::new(&conn.process_name).color(Color32::from_rgb(0, 210, 255)).strong()
                            } else {
                                RichText::new(&conn.process_name).color(Color32::WHITE)
                            };

                            if ui.selectable_label(is_selected, name_label).clicked() {
                                self.selected_conn = Some(conn.clone());
                            }

                            ui.label(format!("{}", conn.pid));

                            let proto_color = match conn.protocol {
                                Protocol::Tcp => Color32::from_rgb(100, 180, 255),
                                Protocol::Udp => Color32::from_rgb(255, 180, 100),
                            };
                            ui.label(RichText::new(format!("{:?}", conn.protocol)).color(proto_color));

                            ui.label(&conn.local_addr);

                            let remote_color = if conn.remote_ip == "*" || conn.remote_ip == "0.0.0.0" || conn.remote_ip == "127.0.0.1" {
                                Color32::GRAY
                            } else {
                                Color32::from_rgb(120, 255, 150)
                            };
                            ui.label(RichText::new(&conn.remote_addr).color(remote_color));

                            let state_color = match conn.state.as_str() {
                                "ESTABLISHED" => Color32::from_rgb(50, 205, 50),
                                "LISTEN" => Color32::from_rgb(100, 150, 255),
                                _ => Color32::LIGHT_GRAY,
                            };
                            ui.label(RichText::new(&conn.state).color(state_color));

                            ui.horizontal(|ui| {
                                if ui.small_button("Inspeksi").clicked() {
                                    self.selected_conn = Some(conn.clone());
                                }
                            });

                            ui.end_row();
                        }
                    });
            });
        });

        // Handle dispatched actions
        if let Some(action) = app_action {
            match action {
                AppAction::ScanFileVt(hash, name) => self.trigger_scan_file_vt(hash, name),
                AppAction::ScanIpVt(ip) => self.trigger_scan_ip_vt(ip),
                AppAction::ScanFileDefender(path) => self.trigger_scan_file_defender(path),
                AppAction::ScanAllDefender => self.trigger_scan_all_defender(),
            }
        }
    }
}

