use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::ptr::null_mut;
use sha2::{Digest, Sha256};
use sysinfo::{ProcessesToUpdate, System};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: String,
    pub protocol: Protocol,
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_ip: String,
    pub state: String,
    pub file_hash: Option<String>,
}

pub struct NetworkScanner {
    sys: System,
    hash_cache: HashMap<String, String>,
}

impl NetworkScanner {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        Self {
            sys,
            hash_cache: HashMap::new(),
        }
    }

    pub fn refresh_processes(&mut self) {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
    }

    pub fn get_process_info(&self, pid: u32) -> (String, Option<String>) {
        let sys_pid = sysinfo::Pid::from_u32(pid);
        if let Some(proc_) = self.sys.process(sys_pid) {
            let name = proc_.name().to_string_lossy().to_string();
            let exe_path = proc_.exe().map(|p| p.to_string_lossy().to_string());
            (name, exe_path)
        } else {
            ("Unknown".to_string(), None)
        }
    }

    pub fn get_file_sha256(&mut self, path_str: &str) -> Option<String> {
        if let Some(cached) = self.hash_cache.get(path_str) {
            return Some(cached.clone());
        }

        let path = PathBuf::from(path_str);
        if !path.exists() || !path.is_file() {
            return None;
        }

        let mut file = File::open(&path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];

        loop {
            let bytes_read = file.read(&mut buffer).ok()?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hex::encode(hasher.finalize());
        self.hash_cache.insert(path_str.to_string(), hash.clone());
        Some(hash)
    }

    pub fn scan_connections(&mut self) -> Vec<ConnectionInfo> {
        self.refresh_processes();
        let mut connections = Vec::new();

        self.collect_tcp_ipv4(&mut connections);
        self.collect_tcp_ipv6(&mut connections);
        self.collect_udp_ipv4(&mut connections);
        self.collect_udp_ipv6(&mut connections);

        connections
    }

    fn collect_tcp_ipv4(&mut self, list: &mut Vec<ConnectionInfo>) {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(
                null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size == 0 {
                return;
            }

            let mut buffer = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret == NO_ERROR {
                let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let count = (*table).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table).table.as_ptr(), count);

                for entry in entries {
                    let local_port = u16::from_be(entry.dwLocalPort as u16);
                    let remote_port = u16::from_be(entry.dwRemotePort as u16);
                    let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                    let remote_ip = Ipv4Addr::from(entry.dwRemoteAddr.to_ne_bytes());
                    let pid = entry.dwOwningPid;
                    let (name, exe) = self.get_process_info(pid);
                    let state_str = tcp_state_to_string(entry.dwState);

                    let remote_ip_str = remote_ip.to_string();
                    let remote_addr_str = if remote_port > 0 {
                        format!("{}:{}", remote_ip_str, remote_port)
                    } else {
                        "-".to_string()
                    };

                    let id = format!("tcp4_{}_{}_{}_{}", pid, local_port, remote_ip_str, remote_port);

                    list.push(ConnectionInfo {
                        id,
                        protocol: Protocol::Tcp,
                        pid,
                        process_name: name,
                        process_path: exe,
                        local_addr: format!("{}:{}", local_ip, local_port),
                        remote_addr: remote_addr_str,
                        remote_ip: remote_ip_str,
                        state: state_str,
                        file_hash: None,
                    });
                }
            }
        }
    }

    fn collect_tcp_ipv6(&mut self, list: &mut Vec<ConnectionInfo>) {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(
                null_mut(),
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size == 0 {
                return;
            }

            let mut buffer = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret == NO_ERROR {
                let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                let count = (*table).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table).table.as_ptr(), count);

                for entry in entries {
                    let local_port = u16::from_be(entry.dwLocalPort as u16);
                    let remote_port = u16::from_be(entry.dwRemotePort as u16);
                    let local_ip = Ipv6Addr::from(entry.ucLocalAddr);
                    let remote_ip = Ipv6Addr::from(entry.ucRemoteAddr);
                    let pid = entry.dwOwningPid;
                    let (name, exe) = self.get_process_info(pid);
                    let state_str = tcp_state_to_string(entry.dwState);

                    let remote_ip_str = remote_ip.to_string();
                    let remote_addr_str = if remote_port > 0 {
                        format!("[{}]:{}", remote_ip_str, remote_port)
                    } else {
                        "-".to_string()
                    };

                    let id = format!("tcp6_{}_{}_{}_{}", pid, local_port, remote_ip_str, remote_port);

                    list.push(ConnectionInfo {
                        id,
                        protocol: Protocol::Tcp,
                        pid,
                        process_name: name,
                        process_path: exe,
                        local_addr: format!("[{}]:{}", local_ip, local_port),
                        remote_addr: remote_addr_str,
                        remote_ip: remote_ip_str,
                        state: state_str,
                        file_hash: None,
                    });
                }
            }
        }
    }

    fn collect_udp_ipv4(&mut self, list: &mut Vec<ConnectionInfo>) {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedUdpTable(
                null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if size == 0 {
                return;
            }

            let mut buffer = vec![0u8; size as usize];
            let ret = GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if ret == NO_ERROR {
                let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                let count = (*table).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table).table.as_ptr(), count);

                for entry in entries {
                    let local_port = u16::from_be(entry.dwLocalPort as u16);
                    let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                    let pid = entry.dwOwningPid;
                    let (name, exe) = self.get_process_info(pid);

                    let id = format!("udp4_{}_{}", pid, local_port);

                    list.push(ConnectionInfo {
                        id,
                        protocol: Protocol::Udp,
                        pid,
                        process_name: name,
                        process_path: exe,
                        local_addr: format!("{}:{}", local_ip, local_port),
                        remote_addr: "*:*".to_string(),
                        remote_ip: "*".to_string(),
                        state: "UDP".to_string(),
                        file_hash: None,
                    });
                }
            }
        }
    }

    fn collect_udp_ipv6(&mut self, list: &mut Vec<ConnectionInfo>) {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedUdpTable(
                null_mut(),
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if size == 0 {
                return;
            }

            let mut buffer = vec![0u8; size as usize];
            let ret = GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if ret == NO_ERROR {
                let table = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
                let count = (*table).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table).table.as_ptr(), count);

                for entry in entries {
                    let local_port = u16::from_be(entry.dwLocalPort as u16);
                    let local_ip = Ipv6Addr::from(entry.ucLocalAddr);
                    let pid = entry.dwOwningPid;
                    let (name, exe) = self.get_process_info(pid);

                    let id = format!("udp6_{}_{}", pid, local_port);

                    list.push(ConnectionInfo {
                        id,
                        protocol: Protocol::Udp,
                        pid,
                        process_name: name,
                        process_path: exe,
                        local_addr: format!("[{}]:{}", local_ip, local_port),
                        remote_addr: "*:*".to_string(),
                        remote_ip: "*".to_string(),
                        state: "UDP".to_string(),
                        file_hash: None,
                    });
                }
            }
        }
    }
}

fn tcp_state_to_string(state: u32) -> String {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
    .to_string()
}
