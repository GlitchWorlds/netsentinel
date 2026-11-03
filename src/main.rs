#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod anomaly;
mod app;
mod defender;
mod net;
mod virustotal;

#[cfg(test)]
mod tests;

use app::NetSentinelApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([800.0, 520.0])
            .with_title("NetSentinel - Network Monitor & VirusTotal"),
        ..Default::default()
    };

    eframe::run_native(
        "NetSentinel",
        options,
        Box::new(|cc| Ok(Box::new(NetSentinelApp::new(cc)))),
    )
}
