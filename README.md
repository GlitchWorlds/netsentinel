# NetSentinel 🛡️⚡

A fast, lightweight, and modern desktop application built in Rust with a native GUI for real-time Windows network connection monitoring, automated heuristic anomaly detection, local Windows Defender antivirus scanning (100% free with no quotas), and VirusTotal threat intelligence.

![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)
![GUI](https://img.shields.io/badge/GUI-egui%20%2F%20eframe-blueviolet.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 🌟 Key Features

### 1. 🚨 Heuristic Network Anomaly Detection
NetSentinel analyzes every active connection in real-time to catch suspicious behavior and stealthy malware:
- **LOLBin Exploitation Detection**: Alerts when system binaries like `powershell.exe`, `cmd.exe`, `rundll32.exe`, `certutil.exe`, or `mshta.exe` make direct outbound connections to external public IPs.
- **Masquerading Detection**: Identifies fake system processes (e.g. `svchost.exe` running outside of `System32` or `explorer.exe` running outside `C:\Windows`).
- **Suspicious Path Execution**: Flags applications running from temporary or untrusted folders (`AppData\Local\Temp`, `Windows\Temp`, `C:\Users\Public`, etc.) that establish outbound connections.
- **Abnormal Port & Protocol Alerts**: Detects outbound connections on ports frequently abused by malware C2, reverse shells, IRC bots, or Tor (e.g. 1337, 4444, 5555, 6667, 9001).
- **Instant Risk Badging**: Every row displays a clear visual risk indicator (**🚨 BAHAYA**, **⚠️ WASPADA**, or **✅ Normal**), with a quick toggle to **"Hanya Anomali"** to filter out benign traffic instantly.

### 2. 🛡️ Free "Scan All" Antivirus Engine (Windows Defender CLI)
- **100% Free & Unlimited**: Integrates directly with your local Microsoft Antimalware engine (`MpCmdRun.exe`).
- **One-Click "Scan All"**: Scans all active running executable binaries with Defender concurrently in the background without incurring API costs or rate limits.
- **99%+ In-the-Wild Malware Detection**: Backed by Microsoft's regularly updated definitions and certified enterprise protection scores.

### 3. 🌐 VirusTotal Cloud Threat Intelligence
- **Executable SHA-256 Hash Scanning**: Query file reputation across 70+ cloud antivirus engines with zero file uploads.
- **Remote Destination IP Reputation**: Instantly inspect remote server IPs to identify command-and-control (C2) servers, botnets, and malicious hostings.
- **Scorecards & Permalinks**: Shows detailed engine detection counts and links directly to full VirusTotal reports in your web browser.

### 4. ⚡ High Performance & Low Footprint
- Native Rust code with non-blocking multi-threaded workers.
- Instant search and filtering by process name, PID, local IP, remote IP, or port.
- Windows IP Helper APIs (`GetExtendedTcpTable`, `GetExtendedUdpTable`) supporting both IPv4 and IPv6.

---

## 🚀 Quick Start (Pre-built Binary)

1. Download **`netsentinel-windows-x64.zip`** from the latest **[Releases](https://github.com/GlitchWorlds/netsentinel/releases)**.
2. Extract the archive.
3. Run `netsentinel.exe` (run as Administrator for full visibility across all system-level processes).
4. *(Optional)* Click **⚙️ Pengaturan** to add your free VirusTotal API key for cloud intelligence.

---

## 🛠️ Building from Source

### Prerequisites
- Rust 1.80+ (`cargo`, `rustc`)
- MinGW-w64 GCC or MSVC C++ Build Tools

```bash
git clone https://github.com/GlitchWorlds/netsentinel.git
cd netsentinel

# Build optimized release binary
cargo build --release
```

The compiled binary will be placed at `target/release/netsentinel.exe`.

---

## 📄 License

This project is licensed under the MIT License.
