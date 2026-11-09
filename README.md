# NetSentinel 🛡️⚡

A fast, lightweight, and modern desktop application built in Rust with a native GUI for real-time Windows network connection monitoring, real-time download/upload traffic meter & session data usage tracking (MB/GB), automated heuristic anomaly detection, local Windows Defender antivirus scanning (100% free with no quotas), VirusTotal cloud threat intelligence, and system auto-start.

![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)
![GUI](https://img.shields.io/badge/GUI-egui%20%2F%20eframe-blueviolet.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-v2.2.0-brightgreen.svg)

---

## 🌟 Key Features

### 1. 🌐 Real-Time Traffic In/Out & Session MB Usage Tracker *(New in v2.2.0)*
- **Live Transfer Rates**: Continuous system-wide tracking of In (Download / Received) and Out (Upload / Transmitted) speeds (in `B/s`, `KB/s`, `MB/s`, and `GB/s`).
- **Cumulative Session Data Tracker**: Accurately computes total MB/GB consumed while NetSentinel is running (`⬇ Masuk`, `⬆ Keluar`, and `📊 Total Selama Terbuka`).
- **Loopback Filtering**: Local loopback interfaces (`127.0.0.1` / `::1`) are automatically excluded so internal IPC doesn't skew internet/LAN data counters.
- **Session Timer & One-Click Reset**: Built-in stopwatch showing session elapsed time (`⏱ 00:15:30`) with a quick `[🔄 Reset Sesi]` button to restart session counting at any time.
- **Per-Interface Tooltip**: Hovering over the traffic stats reveals live per-adapter breakdown (Wi-Fi, Ethernet, VPN, etc.).

### 2. 🚀 System Auto-Start on Windows Boot *(New in v2.2.0)*
- **Native Registry Integration**: Configures `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` using pure native Win32 APIs with zero elevation requirements (no UAC prompt required) and zero console window flashing.
- **Synchronized Status**: Settings directly reflects live Windows Startup state, staying in sync even if toggled via Windows Task Manager.
- **One-Click Toggle**: Enable or disable automatically starting NetSentinel upon user login right from **⚙️ Pengaturan**.

### 3. 🚨 Heuristic Network Anomaly Detection
NetSentinel analyzes every active connection in real-time to catch suspicious behavior and stealthy malware:
- **LOLBin Exploitation Detection**: Alerts when system binaries like `powershell.exe`, `cmd.exe`, `rundll32.exe`, `certutil.exe`, or `mshta.exe` make direct outbound connections to external public IPs.
- **Masquerading Detection**: Identifies fake system processes (e.g. `svchost.exe` running outside of `System32` or `explorer.exe` running outside `C:\Windows`).
- **Suspicious Path Execution**: Flags applications running from temporary or untrusted folders (`AppData\Local\Temp`, `Windows\Temp`, `C:\Users\Public`, etc.) that establish outbound connections.
- **Abnormal Port & Protocol Alerts**: Detects outbound connections on ports frequently abused by malware C2, reverse shells, IRC bots, or Tor (e.g. 1337, 4444, 5555, 6667, 9001).
- **Instant Risk Badging**: Every row displays a clear visual risk indicator (**🚨 BAHAYA**, **⚠️ WASPADA**, or **✅ Normal**), with a quick toggle to **"Hanya Anomali"** to filter out benign traffic instantly.

### 4. 🛡️ Free "Scan All" Antivirus Engine (Windows Defender CLI)
- **100% Free & Unlimited**: Integrates directly with your local Microsoft Antimalware engine (`MpCmdRun.exe`).
- **One-Click "Scan All"**: Scans all active running executable binaries with Defender concurrently in the background without incurring API costs or rate limits.
- **99%+ In-the-Wild Malware Detection**: Backed by Microsoft's regularly updated definitions and certified enterprise protection scores.

### 5. 🌐 VirusTotal Cloud Threat Intelligence
- **Executable SHA-256 Hash Scanning**: Query file reputation across 70+ cloud antivirus engines with zero file uploads.
- **Remote Destination IP Reputation**: Instantly inspect remote server IPs to identify command-and-control (C2) servers, botnets, and malicious hostings.
- **Scorecards & Permalinks**: Shows detailed engine detection counts and links directly to full VirusTotal reports in your web browser.

### 6. 🎨 Full Adaptive Dark & Light Themes
- Native high-contrast color schemes for both Dark Mode and Light Mode with zero unreadable text or low-contrast badges.
- One-click theme switcher (**🌙 Gelap / ☀️ Terang / 🖥️ Sistem**) right in the main toolbar.

---

## 🚀 Quick Start (Pre-built Binary)

1. Download **`netsentinel-windows-x64.zip`** from the latest **[Releases](https://github.com/GlitchWorlds/netsentinel/releases)**.
2. Extract the archive.
3. Run `netsentinel.exe` (run as Administrator for full visibility across all system-level processes).
4. *(Optional)* Click **⚙️ Pengaturan** to enable **System Auto-Start** or add your free VirusTotal API key for cloud threat intelligence.

---

## 🛠️ Building from Source

### Prerequisites
- Rust 1.80+ (`cargo`, `rustc`)
- MinGW-w64 GCC or MSVC C++ Build Tools

```bash
git clone https://github.com/GlitchWorlds/netsentinel.git
cd netsentinel

# Run test suite
cargo test

# Build optimized release binary
cargo build --release
```

The compiled binary will be placed at `target/release/netsentinel.exe`.

---

## 📄 License

This project is licensed under the MIT License.
