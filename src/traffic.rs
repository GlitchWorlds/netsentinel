use std::collections::HashMap;
use std::time::{Duration, Instant};
use sysinfo::Networks;

pub fn is_loopback(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("loopback") || lower == "lo" || lower.starts_with("lo")
}

pub fn bytes_to_mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

pub fn format_speed(bytes_per_sec: f64) -> String {
    let b = if bytes_per_sec.is_nan() || bytes_per_sec < 0.0 {
        0.0
    } else {
        bytes_per_sec
    };

    if b < 1024.0 {
        format!("{:.0} B/s", b)
    } else if b < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", b / 1024.0)
    } else if b < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} MB/s", b / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB/s", b / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_session_mb(bytes: u64) -> String {
    let mb = bytes_to_mb(bytes);
    if bytes >= 1024 * 1024 * 1024 {
        let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        format!("{:.2} MB ({:.2} GB)", mb, gb)
    } else {
        format!("{:.2} MB", mb)
    }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let rem_secs = secs % 60;
    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, mins, rem_secs)
    } else {
        format!("{:02}:{:02}", mins, rem_secs)
    }
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_rate_bps: f64,
    pub tx_rate_bps: f64,
    pub session_rx_bytes: u64,
    pub session_tx_bytes: u64,
    #[allow(dead_code)]
    pub total_rx_bytes: u64,
    #[allow(dead_code)]
    pub total_tx_bytes: u64,
}

pub struct TrafficTracker {
    networks: Networks,
    session_start: Instant,
    last_sample: Instant,
    prev_totals: HashMap<String, (u64, u64)>,
    iface_session: HashMap<String, (u64, u64)>,
    session_rx_bytes: u64,
    session_tx_bytes: u64,
    rx_rate_bps: f64,
    tx_rate_bps: f64,
    interfaces: Vec<InterfaceStats>,
}

impl TrafficTracker {
    pub fn new() -> Self {
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);
        let now = Instant::now();

        let mut prev_totals = HashMap::new();
        for (name, data) in &networks {
            if !is_loopback(name) {
                prev_totals.insert(
                    name.to_string(),
                    (data.total_received(), data.total_transmitted()),
                );
            }
        }

        Self {
            networks,
            session_start: now,
            last_sample: now,
            prev_totals,
            iface_session: HashMap::new(),
            session_rx_bytes: 0,
            session_tx_bytes: 0,
            rx_rate_bps: 0.0,
            tx_rate_bps: 0.0,
            interfaces: Vec::new(),
        }
    }

    pub fn last_sample_elapsed(&self) -> Duration {
        self.last_sample.elapsed()
    }

    pub fn session_duration(&self) -> Duration {
        self.session_start.elapsed()
    }

    pub fn reset_session(&mut self) {
        self.session_rx_bytes = 0;
        self.session_tx_bytes = 0;
        self.session_start = Instant::now();
        self.iface_session.clear();
        for s in &mut self.interfaces {
            s.session_rx_bytes = 0;
            s.session_tx_bytes = 0;
        }
    }

    pub fn refresh(&mut self) {
        self.networks.refresh(true);
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample).as_secs_f64();
        if elapsed < 0.2 {
            return;
        }

        let has_non_loopback = self.networks.iter().any(|(n, _)| !is_loopback(n));

        let mut delta_rx_sum = 0u64;
        let mut delta_tx_sum = 0u64;
        let mut new_iface_stats = Vec::new();

        for (name, data) in &self.networks {
            if has_non_loopback && is_loopback(name) {
                continue;
            }

            let curr_rx = data.total_received();
            let curr_tx = data.total_transmitted();

            let (prev_rx, prev_tx) = self
                .prev_totals
                .get(name)
                .copied()
                .unwrap_or((curr_rx, curr_tx));

            // Compute delta, handling counters wrap or reset gracefully
            let delta_rx = if curr_rx >= prev_rx {
                curr_rx - prev_rx
            } else {
                data.received()
            };

            let delta_tx = if curr_tx >= prev_tx {
                curr_tx - prev_tx
            } else {
                data.transmitted()
            };

            self.prev_totals
                .insert(name.to_string(), (curr_rx, curr_tx));

            delta_rx_sum += delta_rx;
            delta_tx_sum += delta_tx;

            let (if_s_rx, if_s_tx) = self
                .iface_session
                .entry(name.to_string())
                .or_insert((0, 0));
            *if_s_rx += delta_rx;
            *if_s_tx += delta_tx;

            let iface_rx_rate = (delta_rx as f64) / elapsed;
            let iface_tx_rate = (delta_tx as f64) / elapsed;

            new_iface_stats.push(InterfaceStats {
                name: name.to_string(),
                rx_rate_bps: iface_rx_rate,
                tx_rate_bps: iface_tx_rate,
                session_rx_bytes: *if_s_rx,
                session_tx_bytes: *if_s_tx,
                total_rx_bytes: curr_rx,
                total_tx_bytes: curr_tx,
            });
        }

        self.session_rx_bytes += delta_rx_sum;
        self.session_tx_bytes += delta_tx_sum;
        self.rx_rate_bps = (delta_rx_sum as f64) / elapsed;
        self.tx_rate_bps = (delta_tx_sum as f64) / elapsed;
        self.last_sample = now;
        self.interfaces = new_iface_stats;
    }

    pub fn rx_rate_bps(&self) -> f64 {
        self.rx_rate_bps
    }

    pub fn tx_rate_bps(&self) -> f64 {
        self.tx_rate_bps
    }

    pub fn session_rx_bytes(&self) -> u64 {
        self.session_rx_bytes
    }

    pub fn session_tx_bytes(&self) -> u64 {
        self.session_tx_bytes
    }

    pub fn total_session_bytes(&self) -> u64 {
        self.session_rx_bytes + self.session_tx_bytes
    }

    pub fn interfaces(&self) -> &[InterfaceStats] {
        &self.interfaces
    }
}
