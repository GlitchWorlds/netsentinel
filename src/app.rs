use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};

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

pub struct NetSentinelApp {
    scanner: NetworkScanner,
    connections: Vec<ConnectionInfo>,
    search_query: String,
    filter_protocol: Option<Protocol>,
    filter_established_only: bool,

    config: AppConfig,
    show_settings: bool,
    api_key_input: String,

    last_refresh: Instant,
    status_text: String,

    selected_conn: Option<ConnectionInfo>,
    vt_client: VirusTotalClient,

    // Background VT query
    is_scanning_vt: bool,
    active_scan_target: String,
    vt_report: Option<VtScanReport>,
    vt_error: Option<String>,
    vt_rx: Option<Receiver<VtWorkerResult>>,
}

impl NetSentinelApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut scanner = NetworkScanner::new();
        let connections = scanner.scan_connections();
        let config = AppConfig::load();
        let vt_client = VirusTotalClient::new(config.vt_api_key.clone());
        let api_key_input = config.vt_api_key.clone();

        Self {
            scanner,
            connections,
            search_query: String::new(),
            filter_protocol: None,
            filter_established_only: false,
            config,
            show_settings: false,
            api_key_input,
            last_refresh: Instant::now(),
            status_text: "NetSentinel siap. Memindai koneksi jaringan aktif.".to_string(),
            selected_conn: None,
            vt_client,
            is_scanning_vt: false,
            active_scan_target: String::new(),
            vt_report: None,
            vt_error: None,
            vt_rx: None,
        }
    }

    pub fn refresh_network(&mut self) {
        self.connections = self.scanner.scan_connections();
        self.last_refresh = Instant::now();
        self.status_text = format!(
            "Pembaruan selesai: {} koneksi terdeteksi.",
            self.connections.len()
        );
    }

    fn check_vt_background(&mut self) {
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
    }

    fn trigger_scan_file(&mut self, sha256: String, file_name: String) {
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

        let api_key = self.config.vt_api_key.clone();
        thread::spawn(move || {
            let client = VirusTotalClient::new(api_key);
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

    fn trigger_scan_ip(&mut self, ip: String) {
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

        let api_key = self.config.vt_api_key.clone();
        thread::spawn(move || {
            let client = VirusTotalClient::new(api_key);
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
}

impl eframe::App for NetSentinelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_vt_background();

        // Auto refresh tick
        if self.config.auto_refresh
            && self.last_refresh.elapsed() >= Duration::from_secs(self.config.refresh_interval_secs)
            && !self.is_scanning_vt
        {
            self.refresh_network();
        }

        // Request repaint if scanning
        if self.is_scanning_vt {
            ctx.request_repaint_after(Duration::from_millis(300));
        }

        // Action triggers to defer mutable self calls
        let mut scan_file_action: Option<(String, String)> = None;
        let mut scan_ip_action: Option<String> = None;

        // Top Panel: Header & Controls
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("🛡️ NetSentinel").size(20.0).strong().color(Color32::from_rgb(0, 210, 255)));
                ui.label(RichText::new("v1.0.0 | Windows Network Connection Monitor & VirusTotal Checker").color(Color32::GRAY));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙️ Pengaturan").clicked() {
                        self.show_settings = !self.show_settings;
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
                ui.add(egui::TextEdit::singleline(&mut self.search_query).hint_text("Nama proses, PID, IP, port...").desired_width(220.0));

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
                ui.checkbox(&mut self.filter_established_only, "Hanya ESTABLISHED");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("Total: {} koneksi", self.connections.len())).color(Color32::LIGHT_GRAY));
                });
            });
            ui.add_space(6.0);
        });

        // Bottom status bar
        egui::TopBottomPanel::bottom("bottom_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status_text).size(12.0).color(Color32::LIGHT_GRAY));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let has_key = if self.vt_client.has_api_key() {
                        RichText::new("VT API: Terhubung").color(Color32::GREEN)
                    } else {
                        RichText::new("VT API: Belum Ada Key").color(Color32::GOLD)
                    };
                    ui.label(has_key);
                });
            });
        });

        // Settings Dialog Window
        if self.show_settings {
            egui::Window::new("⚙️ Pengaturan NetSentinel")
                .collapsible(false)
                .resizable(false)
                .default_size(Vec2::new(420.0, 220.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.heading("Konfigurasi VirusTotal API");
                    ui.label("Masukkan API Key gratis Anda dari virustotal.com untuk mengaktifkan pemindaian hash berkas dan reputasi IP secara otomatis.");

                    ui.add_space(8.0);
                    ui.label("VirusTotal API Key:");
                    ui.add(egui::TextEdit::singleline(&mut self.api_key_input).password(true).desired_width(380.0));

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Interval Auto Refresh (detik):");
                        let mut interval = self.config.refresh_interval_secs;
                        if ui.add(egui::Slider::new(&mut interval, 1..=30).suffix(" s")).changed() {
                            self.config.refresh_interval_secs = interval;
                        }
                    });

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
                            if ui.link("Dapatkan API Key Gratis").clicked() {
                                let _ = webbrowser::open("https://www.virustotal.com/gui/my-apikey");
                            }
                        });
                    });
                });
        }

        // Side panel: Inspection & VirusTotal Result
        egui::SidePanel::right("side_inspector")
            .min_width(320.0)
            .default_width(340.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading(RichText::new("🔬 Inspeksi & VirusTotal").size(16.0).strong());
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

                    ui.add_space(8.0);
                    ui.separator();
                    ui.heading(RichText::new("Tindakan VirusTotal").size(14.0));

                    ui.add_space(4.0);
                    if self.is_scanning_vt {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(format!("Memeriksa {}...", self.active_scan_target));
                        });
                    } else {
                        // Scan file hash button
                        if let Some(ref path) = conn.process_path {
                            let mut scanner = NetworkScanner::new();
                            if let Some(hash) = scanner.get_file_sha256(path) {
                                ui.label(RichText::new("SHA256 Executable:").size(11.0).color(Color32::GRAY));
                                ui.monospace(format!("{}...", &hash[..16.min(hash.len())]));

                                if ui.button("🔍 Cek Berkas di VirusTotal").clicked() {
                                    scan_file_action = Some((hash, conn.process_name.clone()));
                                }
                            }
                        }

                        // Scan remote IP button
                        if conn.remote_ip != "*" && conn.remote_ip != "0.0.0.0" && conn.remote_ip != "127.0.0.1" && conn.remote_ip != "::1" && !conn.remote_ip.is_empty() {
                            let ip = conn.remote_ip.clone();
                            if ui.button(format!("🌐 Cek IP {} di VirusTotal", ip)).clicked() {
                                scan_ip_action = Some(ip);
                            }
                        }
                    }

                    // Display VT Report
                    ui.add_space(8.0);
                    if let Some(ref err) = self.vt_error {
                        ui.group(|ui| {
                            ui.label(RichText::new("⚠️ Catatan / Peringatan:").color(Color32::GOLD).strong());
                            ui.label(err);
                        });
                    }

                    if let Some(ref report) = self.vt_report {
                        ui.group(|ui| {
                            ui.label(RichText::new("📊 Hasil Analisis VirusTotal").strong().color(Color32::WHITE));
                            ui.label(format!("Target: {}", report.target));

                            ui.add_space(4.0);
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
                                ui.label(RichText::new("🚨 PERINGATAN: Berkas/IP terdeteksi berbahaya!").color(Color32::from_rgb(255, 75, 75)).strong());
                            } else {
                                ui.label(RichText::new("✅ Bersih / Tidak terdeteksi ancaman").color(Color32::from_rgb(50, 205, 50)));
                            }

                            if !report.top_detections.is_empty() {
                                ui.add_space(4.0);
                                ui.label(RichText::new("Deteksi Mesin AV:").strong());
                                for det in report.top_detections.iter().take(5) {
                                    ui.label(RichText::new(format!("• {}", det)).size(11.0).color(Color32::from_rgb(255, 120, 120)));
                                }
                            }

                            ui.add_space(6.0);
                            let permalink = report.permalink.clone();
                            if ui.button("🌐 Buka Laporan Lengkap di Browser").clicked() {
                                let _ = webbrowser::open(&permalink);
                            }
                        });
                    }
                } else {
                    ui.add_space(20.0);
                    ui.label("Pilih salah satu koneksi dari tabel di sebelah kiri untuk melihat detail aplikasi, hash executable, dan memeriksa reputasi di VirusTotal.");
                }
            });

        // Central Panel: Connection Table
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
                    .min_col_width(80.0)
                    .show(ui, |ui| {
                        // Header
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

        // Trigger deferred actions
        if let Some((hash, name)) = scan_file_action {
            self.trigger_scan_file(hash, name);
        }
        if let Some(ip) = scan_ip_action {
            self.trigger_scan_ip(ip);
        }
    }
}
