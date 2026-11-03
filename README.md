# NetSentinel 🛡️⚡

A fast, lightweight, and modern desktop application built with Rust and native GUI for real-time Windows network connection monitoring, process inspection, and automated VirusTotal intelligence scanning.

![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)
![GUI](https://img.shields.io/badge/GUI-egui%20%2F%20eframe-blueviolet.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## Features

- **Live Network Connection Monitoring**:
  - Monitors all active TCP and UDP sockets across IPv4 and IPv6 using native Windows IP Helper APIs (`GetExtendedTcpTable`, `GetExtendedUdpTable`).
  - Identifies which application / process name and PID opened each connection.
  - Resolves local address, remote destination IP, port numbers, and socket states (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, etc.).

- **Application & Process Inspection**:
  - Automatically maps active network sockets to the exact executable path on disk.
  - Direct button to open the application's file location in Windows Explorer.
  - Instant SHA-256 cryptographic hash computation for suspicious binaries.

- **VirusTotal Integration**:
  - **File Hash Reputation**: Check any active process binary against 70+ antivirus engines on VirusTotal with a single click.
  - **Remote IP Reputation**: Check destination server/IP addresses against VirusTotal threat intelligence databases.
  - Live analysis scorecard (Malicious, Suspicious, Harmless, Undetected) with direct permalinks to full web reports.
  - Secure local configuration for storing your free VirusTotal API key.

- **Filtering & Ergonomics**:
  - Real-time search filter by process name, PID, local IP, remote IP, or port.
  - Protocol filters (All, TCP, UDP) and connection state filters (e.g. Established only).
  - Configurable auto-refresh interval with background non-blocking worker threads.

---

## Quick Start (Pre-built Binary)

1. Download `netsentinel-windows-x64.zip` from the latest **[Releases](https://github.com/GlitchWorlds/netsentinel/releases)**.
2. Extract the archive.
3. Run `netsentinel.exe`. (No runtime installation required).
4. *(Optional)* Click **⚙️ Pengaturan** in the top-right corner to input your free VirusTotal API key to enable instant malware reputation checks.

---

## Building from Source

### Prerequisites
- Rust 1.80+ (`cargo`, `rustc`)
- A C compiler / linker (GCC MinGW-w64 or MSVC build tools)

### Build
```bash
# Clone the repository
git clone https://github.com/GlitchWorlds/netsentinel.git
cd netsentinel

# Build optimized release binary
cargo build --release
```

The compiled standalone executable will be located at `target/release/netsentinel.exe`.

---

## License

This project is licensed under the MIT License.
