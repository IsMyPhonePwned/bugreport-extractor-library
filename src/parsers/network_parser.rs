use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;

#[derive(Debug, Clone)]
struct SocketConnection {
    protocol: String,
    local_address: String,  // Combined format for backward compatibility
    remote_address: String, // Combined format for backward compatibility
    local_ip: Option<String>,    // Extracted IP address
    local_port: Option<u16>,     // Extracted port
    remote_ip: Option<String>,   // Extracted IP address
    remote_port: Option<u16>,    // Extracted port
    state: Option<String>,
    uid: Option<u32>,
    inode: Option<u64>,
    recv_q: Option<u32>,
    send_q: Option<u32>,
    socket_key: Option<String>,
    additional_info: Option<String>, // For TCP details from ss command
}

impl SocketConnection {
    fn make_key(&self) -> String {
        // Create a unique key based on protocol, local, and remote addresses
        format!("{}|{}|{}", self.protocol, self.local_address, self.remote_address)
    }
    
    fn merge(&mut self, other: &SocketConnection) {
        // Merge data from another socket connection, preferring non-None values
        // Normalize state format: both "SYN_SENT" and "SYN-SENT" should be treated the same
        if let Some(ref other_state) = other.state {
            // If we have a state, prefer the one that's not just "0x..." (from /proc/net/)
            if self.state.is_none() || (self.state.as_ref().unwrap().starts_with("0x") && !other_state.starts_with("0x")) {
                // Normalize hyphens to underscores for consistency
                self.state = Some(other_state.replace("-", "_"));
            }
        }
        if self.uid.is_none() {
            self.uid = other.uid;
        }
        if self.inode.is_none() {
            self.inode = other.inode;
        }
        if self.recv_q.is_none() {
            self.recv_q = other.recv_q;
        }
        if self.send_q.is_none() {
            self.send_q = other.send_q;
        }
        if self.socket_key.is_none() {
            self.socket_key = other.socket_key.clone();
        }
        // Merge IP and port fields
        if self.local_ip.is_none() {
            self.local_ip = other.local_ip.clone();
        }
        if self.local_port.is_none() {
            self.local_port = other.local_port;
        }
        if self.remote_ip.is_none() {
            self.remote_ip = other.remote_ip.clone();
        }
        if self.remote_port.is_none() {
            self.remote_port = other.remote_port;
        }
        // Additional info from ss command is more detailed, prefer it
        if other.additional_info.is_some() {
            self.additional_info = other.additional_info.clone();
        }
    }
}

#[derive(Debug, Clone)]
struct NetworkInterface {
    name: String,
    ip_addresses: Vec<String>,
    flags: Vec<String>,
    mtu: Option<u32>,
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
struct NetworkStats {
    uid: Option<i32>, // UIDs can be negative (e.g., -1 for system stats)
    package_name: Option<String>,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: Option<u64>,
    tx_packets: Option<u64>,
    // Interface information from ident field
    network_type: Option<String>, // "WIFI" or "MOBILE"
    wifi_network_name: Option<String>, // WiFi network SSID/key (from wifiNetworkKey)
    subscriber_id: Option<String>, // Mobile network subscriber ID
    rat_type: Option<String>, // Radio access technology type (e.g., "3", "COMBINED")
    metered: Option<bool>, // Whether network is metered
    default_network: Option<bool>, // Whether this is the default network
}

/// A parser for network-related sections in Android bug reports.
/// Parses socket connections, network interfaces, and network statistics.
pub struct NetworkParser;

impl Default for NetworkParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Network Parser")
    }
}

impl NetworkParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(NetworkParser)
    }

    fn parse_hex_or_decimal(s: &str) -> Option<u64> {
        // Try parsing as hexadecimal first (common in network stats)
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).ok()
        } else {
            s.parse().ok()
        }
    }

    // Parse ident field to extract network interface information
    // Format: ident=[{type=1, ratType=COMBINED, wifiNetworkKey="Fraise"wpa2-psk, metered=false, defaultNetwork=true, ...}]
    fn parse_ident_field(ident_line: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>, Option<bool>, Option<bool>) {
        let mut network_type = None;
        let mut wifi_network_name = None;
        let mut subscriber_id = None;
        let mut rat_type = None;
        let mut metered = None;
        let mut default_network = None;

        // Extract the content between ident=[{ and }]
        if let Some(start) = ident_line.find("ident=[{") {
            if let Some(end) = ident_line[start + 8..].find("}]") {
                let ident_content = &ident_line[start + 8..start + 8 + end];
                
                // Parse key=value pairs
                for part in ident_content.split(',') {
                    let part = part.trim();
                    if let Some((key, value)) = part.split_once('=') {
                        let key = key.trim();
                        let value = value.trim();
                        
                        match key {
                            "type" => {
                                // type=0 is MOBILE, type=1 is WIFI
                                if value == "0" {
                                    network_type = Some("MOBILE".to_string());
                                } else if value == "1" {
                                    network_type = Some("WIFI".to_string());
                                }
                            }
                            "wifiNetworkKey" => {
                                // Extract WiFi network name, removing quotes and security type
                                // Format: "Fraise"wpa2-psk -> "Fraise"
                                if let Some(quote_start) = value.find('"') {
                                    if let Some(quote_end) = value[quote_start + 1..].find('"') {
                                        wifi_network_name = Some(value[quote_start + 1..quote_start + 1 + quote_end].to_string());
                                    }
                                }
                            }
                            "subscriberId" => {
                                // Remove trailing ellipsis if present
                                let sub_id = if value.ends_with("...") {
                                    &value[..value.len() - 3]
                                } else {
                                    value
                                };
                                subscriber_id = Some(sub_id.to_string());
                            }
                            "ratType" => {
                                rat_type = Some(value.to_string());
                            }
                            "metered" => {
                                metered = Some(value == "true");
                            }
                            "defaultNetwork" => {
                                default_network = Some(value == "true");
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        (network_type, wifi_network_name, subscriber_id, rat_type, metered, default_network)
    }

    fn parse_ip_address(hex_str: &str) -> String {
        // Parse IP address from hex format (e.g., "0100007F" = 127.0.0.1)
        // Format is typically 4 bytes in hex, but could be IPv6 (16 bytes)
        if hex_str.len() == 8 {
            // IPv4: 4 bytes
            if let (Ok(b1), Ok(b2), Ok(b3), Ok(b4)) = (
                u8::from_str_radix(&hex_str[0..2], 16),
                u8::from_str_radix(&hex_str[2..4], 16),
                u8::from_str_radix(&hex_str[4..6], 16),
                u8::from_str_radix(&hex_str[6..8], 16),
            ) {
                return format!("{}.{}.{}.{}", b4, b3, b2, b1); // Network byte order
            }
        }
        hex_str.to_string()
    }

    fn parse_port(hex_str: &str) -> String {
        // Parse port from hex format (e.g., "D431" = 54321)
        if hex_str.len() == 4 {
            if let Ok(port) = u16::from_str_radix(hex_str, 16) {
                // Network byte order
                return format!("{}", u16::from_be(port));
            }
        }
        hex_str.to_string()
    }

    // Parse address:port string and return (address, port)
    // Handles formats like "192.168.1.1:8080", "[::1]:8080", "*:*", "0.0.0.0:0"
    fn parse_address_port(addr_port: &str) -> (String, Option<u16>) {
        // Handle IPv6 addresses in brackets: [::1]:8080
        if addr_port.starts_with('[') {
            if let Some(bracket_end) = addr_port.find(']') {
                if let Some(colon_after_bracket) = addr_port[bracket_end + 1..].find(':') {
                    let ip = addr_port[1..bracket_end].to_string();
                    let port_str = &addr_port[bracket_end + 1 + colon_after_bracket + 1..];
                    let port = port_str.parse::<u16>().ok();
                    return (ip, port);
                }
            }
        }
        
        // Handle regular format: address:port or *:*
        if let Some(colon_pos) = addr_port.rfind(':') {
            let address = addr_port[..colon_pos].to_string();
            let port_str = &addr_port[colon_pos + 1..];
            let port = if port_str == "*" || port_str.is_empty() {
                None
            } else {
                port_str.parse::<u16>().ok()
            };
            (address, port)
        } else {
            // No port found, just address
            (addr_port.to_string(), None)
        }
    }
}

impl Parser for NetworkParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut result = Map::new();

        let mut socket_map: std::collections::HashMap<String, SocketConnection> = std::collections::HashMap::new();
        let mut interfaces: Vec<NetworkInterface> = Vec::new();
        let mut network_stats: Vec<NetworkStats> = Vec::new();

        // Parse NETSTAT section (socket connections)
        const NETSTAT_DELIMITER: &str = "------ NETSTAT";
        const NETSTAT_END: &str = "------";
        
        if let Some(start_index) = content.find(NETSTAT_DELIMITER) {
            let netstat_content = &content[start_index..];
            let lines: Vec<&str> = netstat_content
                .lines()
                .skip(1) // Skip the delimiter line itself
                .take_while(|&line| {
                    let trimmed = line.trim();
                    !(trimmed.starts_with(NETSTAT_END) && trimmed != NETSTAT_DELIMITER)
                })
                .collect();

            for line in lines {
                let trimmed = line.trim();
                
                // Skip header lines and empty lines
                if trimmed.is_empty() || trimmed.starts_with("Proto") || trimmed.starts_with("Active") {
                    continue;
                }

                // Parse TCP/UDP connection lines
                // Format: tcp        0      1 192.168.8.183:55191                                 51.116.253.169:443                                  SYN_SENT    1010351    1136844     -
                // Columns: Proto Recv-Q Send-Q Local Address Foreign Address State User Inode PID/Program
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    let protocol = parts[0].to_lowercase();
                    if protocol == "tcp" || protocol == "udp" || protocol == "tcp6" || protocol == "udp6" || protocol == "raw6" {
                        let recv_q = if parts.len() > 1 {
                            parts[1].parse().ok()
                        } else {
                            None
                        };
                        let send_q = if parts.len() > 2 {
                            parts[2].parse().ok()
                        } else {
                            None
                        };
                        let local_addr = if parts.len() > 3 {
                            parts[3].to_string()
                        } else {
                            "*:*".to_string()
                        };
                        let remote_addr = if parts.len() > 4 {
                            parts[4].to_string()
                        } else {
                            "*:*".to_string()
                        };
                        let state = if protocol.starts_with("tcp") && parts.len() > 5 {
                            Some(parts[5].to_string())
                        } else if protocol == "udp" || protocol == "udp6" {
                            if parts.len() > 5 {
                                Some(parts[5].to_string())
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        
                        // Parse User (UID) and Inode - these are typically columns 6 and 7
                        let mut uid = None;
                        let mut inode = None;
                        
                        // Try to find UID and inode in the remaining fields
                        // In netstat format, they appear as separate columns: "1010351    1136844"
                        if parts.len() > 6 {
                            // Try column 6 as UID
                            uid = parts[6].parse().ok();
                        }
                        if parts.len() > 7 {
                            // Try column 7 as inode
                            inode = parts[7].parse().ok();
                        }
                        
                        // Also check for uid: and ino: patterns (from ss command format)
                        for part in &parts {
                            if let Some(uid_str) = part.strip_prefix("uid:") {
                                uid = uid_str.parse().ok();
                            } else if let Some(ino_str) = part.strip_prefix("ino:") {
                                inode = ino_str.parse().ok();
                            } else if part.starts_with("0x") {
                                inode = Self::parse_hex_or_decimal(part);
                            }
                        }

                        // Parse addresses and ports
                        let (local_ip, local_port) = Self::parse_address_port(&local_addr);
                        let (remote_ip, remote_port) = Self::parse_address_port(&remote_addr);

                        let mut socket = SocketConnection {
                            protocol,
                            local_address: local_addr,
                            remote_address: remote_addr,
                            local_ip: Some(local_ip),
                            local_port,
                            remote_ip: Some(remote_ip),
                            remote_port,
                            state,
                            uid,
                            inode,
                            recv_q,
                            send_q,
                            socket_key: None,
                            additional_info: None,
                        };
                        
                        let key = socket.make_key();
                        socket_map.insert(key, socket);
                    }
                }

                // Parse /proc/net/ format (hex addresses)
                // Format: sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
                if trimmed.starts_with("sl") || trimmed.matches('\t').count() >= 8 {
                    let fields: Vec<&str> = trimmed.split_whitespace().collect();
                    if fields.len() >= 10 {
                        let local_hex = fields[1];
                        let remote_hex = fields[2];
                        let state_hex = fields[3];
                        let uid_str = fields[7];
                        let inode_str = fields[9];

                        // Parse local address (format: "0100007F:D431" = 127.0.0.1:54321)
                        let (local_ip_hex, local_port_hex) = if let Some(colon) = local_hex.find(':') {
                            (&local_hex[..colon], &local_hex[colon + 1..])
                        } else {
                            (local_hex, "0000")
                        };
                        
                        let (remote_ip_hex, remote_port_hex) = if let Some(colon) = remote_hex.find(':') {
                            (&remote_hex[..colon], &remote_hex[colon + 1..])
                        } else {
                            (remote_hex, "0000")
                        };

                        let local_addr = format!("{}:{}", 
                            Self::parse_ip_address(local_ip_hex),
                            Self::parse_port(local_port_hex));
                        let remote_addr = format!("{}:{}",
                            Self::parse_ip_address(remote_ip_hex),
                            Self::parse_port(remote_port_hex));

                        // Parse addresses and ports
                        let (local_ip, local_port) = Self::parse_address_port(&local_addr);
                        let (remote_ip, remote_port) = Self::parse_address_port(&remote_addr);

                        let mut socket = SocketConnection {
                            protocol: "tcp".to_string(),
                            local_address: local_addr,
                            remote_address: remote_addr,
                            local_ip: Some(local_ip),
                            local_port,
                            remote_ip: Some(remote_ip),
                            remote_port,
                            state: Some(format!("0x{}", state_hex)),
                            uid: uid_str.parse().ok(),
                            inode: inode_str.parse().ok(),
                            recv_q: None,
                            send_q: None,
                            socket_key: None,
                            additional_info: None,
                        };
                        
                        let key = socket.make_key();
                        socket_map.insert(key, socket);
                    }
                }
            }
        }

        // Parse DETAILED SOCKET STATE section (ss -eionptu)
        const SS_DELIMITER: &str = "------ DETAILED SOCKET STATE";
        
        if let Some(start_index) = content.find(SS_DELIMITER) {
            let ss_content = &content[start_index..];
            let lines: Vec<&str> = ss_content
                .lines()
                .skip(1) // Skip the delimiter line itself
                .take_while(|&line| {
                    let trimmed = line.trim();
                    !(trimmed.starts_with("------") && trimmed != SS_DELIMITER)
                })
                .collect();

            let mut current_socket: Option<SocketConnection> = None;
            let mut additional_lines = Vec::new();

            for line in lines {
                let trimmed = line.trim();
                
                // Skip header lines
                if trimmed.is_empty() || trimmed.starts_with("Netid") || trimmed.starts_with("State") {
                    continue;
                }
                
                // Check if this is a continuation line (starts with tab or leading spaces) - check original line before trimming
                let is_continuation = line.starts_with('\t') || (line.len() > 0 && line.chars().take(4).all(|c| c == ' '));
                
                if !is_continuation {
                    // New socket line - save previous one if exists
                    if let Some(mut socket) = current_socket.take() {
                        if !additional_lines.is_empty() {
                            socket.additional_info = Some(additional_lines.join("\n"));
                        }
                        let key = socket.make_key();
                        if let Some(existing) = socket_map.get_mut(&key) {
                            existing.merge(&socket);
                        } else {
                            socket_map.insert(key, socket);
                        }
                    }
                    additional_lines.clear();
                    
                    // Parse socket line: "tcp    SYN-SENT   0      1      192.168.8.183:55191              51.116.253.169:443                 timer:(on,1.484ms,7) uid:1010351 ino:1136844 sk:9087 <->"
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let protocol = parts[0].to_lowercase();
                        if protocol == "tcp" || protocol == "udp" || protocol == "tcp6" || protocol == "udp6" || protocol == "raw6" {
                            let state_str = parts[1].to_string();
                            let recv_q = parts[2].parse().ok();
                            let send_q = parts[3].parse().ok();
                            let local_addr = parts[4].to_string();
                            let remote_addr = if parts.len() > 5 {
                                parts[5].to_string()
                            } else {
                                "*:*".to_string()
                            };
                            
                            // Extract UID, inode, and socket key from remaining fields
                            let mut uid = None;
                            let mut inode = None;
                            let mut socket_key = None;
                            
                            for part in &parts {
                                if let Some(uid_str) = part.strip_prefix("uid:") {
                                    uid = uid_str.parse().ok();
                                } else if let Some(ino_str) = part.strip_prefix("ino:") {
                                    inode = ino_str.parse().ok();
                                } else if let Some(sk_str) = part.strip_prefix("sk:") {
                                    socket_key = Some(sk_str.to_string());
                                }
                            }
                            
                            // Parse addresses and ports
                            let (local_ip, local_port) = Self::parse_address_port(&local_addr);
                            let (remote_ip, remote_port) = Self::parse_address_port(&remote_addr);

                            current_socket = Some(SocketConnection {
                                protocol,
                                local_address: local_addr,
                                remote_address: remote_addr,
                                local_ip: Some(local_ip),
                                local_port,
                                remote_ip: Some(remote_ip),
                                remote_port,
                                state: Some(state_str),
                                uid,
                                inode,
                                recv_q,
                                send_q,
                                socket_key,
                                additional_info: None,
                            });
                        }
                    }
                } else if current_socket.is_some() {
                    // Continuation line with additional TCP info
                    additional_lines.push(trimmed.to_string());
                }
            }
            
            // Save last socket if exists
            if let Some(mut socket) = current_socket {
                if !additional_lines.is_empty() {
                    socket.additional_info = Some(additional_lines.join("\n"));
                }
                let key = socket.make_key();
                if let Some(existing) = socket_map.get_mut(&key) {
                    existing.merge(&socket);
                } else {
                    socket_map.insert(key, socket);
                }
            }
        }

        // Parse CHECKIN NETSTATS section (dumpsys netstats)
        // Format: ident=[...] uid=XXXX set=... tag=...
        //         NetworkStatsHistory: bucketDuration=...
        //           st=... rb=... rp=... tb=... tp=... op=...
        const NETSTATS_DELIMITER: &str = "------ CHECKIN NETSTATS";
        const NETSTATS_END: &str = "------";
        
        if let Some(start_index) = content.find(NETSTATS_DELIMITER) {
            let netstats_content = &content[start_index..];
            let lines = netstats_content
                .lines()
                .skip(1) // Skip the delimiter line itself
                .take_while(|&line| {
                    let trimmed = line.trim();
                    !(trimmed.starts_with(NETSTATS_END) && !trimmed.contains(NETSTATS_DELIMITER))
                });

            let mut current_uid: Option<i32> = None;
            let mut current_packages: Vec<String> = Vec::new();
            let mut current_network_type: Option<String> = None;
            let mut current_wifi_network_name: Option<String> = None;
            let mut current_subscriber_id: Option<String> = None;
            let mut current_rat_type: Option<String> = None;
            let mut current_metered: Option<bool> = None;
            let mut current_default_network: Option<bool> = None;
            let mut in_history = false;
            let mut total_rx_bytes = 0u64;
            let mut total_tx_bytes = 0u64;
            let mut total_rx_packets = 0u64;
            let mut total_tx_packets = 0u64;
            
            for line in lines {
                let trimmed = line.trim();
                
                // Parse UID from ident line: "ident=[...] uid=1005009 set=FOREGROUND tag=0x0"
                // Or from separate line: "uid=10050 packages=..." or just "uid=10050"
                let mut found_new_uid = false;
                
                if trimmed.starts_with("ident=") && trimmed.contains("uid=") {
                    found_new_uid = true;
                } else if trimmed.starts_with("uid=") {
                    // UID on separate line (with or without packages)
                    found_new_uid = true;
                }
                
                if found_new_uid {
                    // Save previous stats if any
                    if current_uid.is_some() && (total_rx_bytes > 0 || total_tx_bytes > 0) {
                        for package in &current_packages {
                            network_stats.push(NetworkStats {
                                uid: current_uid,
                                package_name: Some(package.clone()),
                                rx_bytes: total_rx_bytes,
                                tx_bytes: total_tx_bytes,
                                rx_packets: Some(total_rx_packets),
                                tx_packets: Some(total_tx_packets),
                                network_type: current_network_type.clone(),
                                wifi_network_name: current_wifi_network_name.clone(),
                                subscriber_id: current_subscriber_id.clone(),
                                rat_type: current_rat_type.clone(),
                                metered: current_metered,
                                default_network: current_default_network,
                            });
                        }
                        // Also add entry without package if no packages found
                        if current_packages.is_empty() {
                            network_stats.push(NetworkStats {
                                uid: current_uid,
                                package_name: None,
                                rx_bytes: total_rx_bytes,
                                tx_bytes: total_tx_bytes,
                                rx_packets: Some(total_rx_packets),
                                tx_packets: Some(total_tx_packets),
                                network_type: current_network_type.clone(),
                                wifi_network_name: current_wifi_network_name.clone(),
                                subscriber_id: current_subscriber_id.clone(),
                                rat_type: current_rat_type.clone(),
                                metered: current_metered,
                                default_network: current_default_network,
                            });
                        }
                    }
                    
                    // Reset for new UID
                    total_rx_bytes = 0;
                    total_tx_bytes = 0;
                    total_rx_packets = 0;
                    total_tx_packets = 0;
                    current_packages.clear();
                    current_network_type = None;
                    current_wifi_network_name = None;
                    current_subscriber_id = None;
                    current_rat_type = None;
                    current_metered = None;
                    current_default_network = None;
                    in_history = false;
                    
                    // Parse ident field if present to extract interface information
                    if trimmed.starts_with("ident=") {
                        let (net_type, wifi_name, sub_id, rat, met, def_net) = Self::parse_ident_field(trimmed);
                        current_network_type = net_type;
                        current_wifi_network_name = wifi_name;
                        current_subscriber_id = sub_id;
                        current_rat_type = rat;
                        current_metered = met;
                        current_default_network = def_net;
                    }
                    
                    // Extract UID (can be negative, e.g., -1 for system stats)
                    if let Some(uid_start) = trimmed.find("uid=") {
                        let uid_part = &trimmed[uid_start + 4..];
                        if let Some(space_pos) = uid_part.find(' ') {
                            current_uid = uid_part[..space_pos].parse::<i32>().ok();
                        } else {
                            current_uid = uid_part.parse::<i32>().ok();
                        }
                    }
                }
                
                // Check if we're entering a NetworkStatsHistory section
                if trimmed.starts_with("NetworkStatsHistory:") {
                    in_history = true;
                    continue;
                }
                
                // Parse history entries: "st=1758002400 rb=7183 rp=15 tb=3671 tp=16 op=0"
                if in_history && trimmed.starts_with("st=") {
                    for part in trimmed.split_whitespace() {
                        if let Some((key, value)) = part.split_once('=') {
                            if let Ok(val) = value.parse::<u64>() {
                                match key {
                                    "rb" => total_rx_bytes += val,
                                    "tb" => total_tx_bytes += val,
                                    "rp" => total_rx_packets += val,
                                    "tp" => total_tx_packets += val,
                                    _ => {}
                                }
                            }
                        }
                    }
                } else if !trimmed.starts_with("st=") && !trimmed.starts_with("NetworkStatsHistory:") && !trimmed.starts_with("ident=") {
                    // If we see a non-history line (and not ident or st), we're out of the history section
                    in_history = false;
                }
                
                // Parse package names from lines like: "  uid=10050 packages=com.android.systemui com.samsung.android.app.aodservice"
                // This can appear before or after the ident line, and may include the uid
                if trimmed.contains("packages=") {
                    // Extract UID if present on same line (can be negative)
                    if trimmed.starts_with("uid=") {
                        if let Some(uid_start) = trimmed.find("uid=") {
                            let uid_part = &trimmed[uid_start + 4..];
                            if let Some(space_pos) = uid_part.find(' ') {
                                current_uid = uid_part[..space_pos].parse::<i32>().ok();
                            } else {
                                current_uid = uid_part.parse::<i32>().ok();
                            }
                        }
                    }
                    
                    if let Some(packages_start) = trimmed.find("packages=") {
                        let packages_part = &trimmed[packages_start + 9..];
                        current_packages = packages_part.split_whitespace().map(|s| s.to_string()).collect();
                    }
                }
            }
            
            // Save last stats if any
            if current_uid.is_some() && (total_rx_bytes > 0 || total_tx_bytes > 0) {
                for package in &current_packages {
                    network_stats.push(NetworkStats {
                        uid: current_uid,
                        package_name: Some(package.clone()),
                        rx_bytes: total_rx_bytes,
                        tx_bytes: total_tx_bytes,
                        rx_packets: Some(total_rx_packets),
                        tx_packets: Some(total_tx_packets),
                        network_type: current_network_type.clone(),
                        wifi_network_name: current_wifi_network_name.clone(),
                        subscriber_id: current_subscriber_id.clone(),
                        rat_type: current_rat_type.clone(),
                        metered: current_metered,
                        default_network: current_default_network,
                    });
                }
                if current_packages.is_empty() {
                    network_stats.push(NetworkStats {
                        uid: current_uid,
                        package_name: None,
                        rx_bytes: total_rx_bytes,
                        tx_bytes: total_tx_bytes,
                        rx_packets: Some(total_rx_packets),
                        tx_packets: Some(total_tx_packets),
                        network_type: current_network_type.clone(),
                        wifi_network_name: current_wifi_network_name.clone(),
                        subscriber_id: current_subscriber_id.clone(),
                        rat_type: current_rat_type.clone(),
                        metered: current_metered,
                        default_network: current_default_network,
                    });
                }
            }
        }

        // Parse NETWORK DEV INFO section (/proc/net/dev)
        const NETDEV_DELIMITER: &str = "------ NETWORK DEV INFO";
        
        if let Some(start_index) = content.find(NETDEV_DELIMITER) {
            let netdev_content = &content[start_index..];
            let lines: Vec<&str> = netdev_content
                .lines()
                .skip(1) // Skip the delimiter line itself
                .take_while(|&line| {
                    let trimmed = line.trim();
                    !(trimmed.starts_with("------") && trimmed != NETDEV_DELIMITER)
                })
                .collect();

            for line in lines {
                let trimmed = line.trim();
                
                // Skip header lines
                if trimmed.is_empty() || trimmed.starts_with("Inter-") || trimmed.starts_with("face") {
                    continue;
                }
                
                // Parse interface stats line: "  wlan0: 128362872  110953    0    0    0     0          0         0 11470306   38427   10    0    0     0       0          0"
                if trimmed.contains(':') {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 10 {
                        let iface_name = parts[0].trim_end_matches(':').to_string();
                        
                        // Fields: rx_bytes, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast,
                        //         tx_bytes, tx_packets, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed
                        let rx_bytes = parts[1].parse::<u64>().ok();
                        let tx_bytes = parts[9].parse::<u64>().ok();
                        
                        // Find or create interface entry
                        let iface = interfaces.iter_mut().find(|i| i.name == iface_name);
                        if let Some(iface) = iface {
                            if rx_bytes.is_some() {
                                iface.rx_bytes = rx_bytes;
                            }
                            if tx_bytes.is_some() {
                                iface.tx_bytes = tx_bytes;
                            }
                        } else {
                            // Create new interface entry
                            interfaces.push(NetworkInterface {
                                name: iface_name,
                                ip_addresses: Vec::new(),
                                flags: Vec::new(),
                                mtu: None,
                                rx_bytes,
                                tx_bytes,
                            });
                        }
                    }
                }
            }
        }

        // Parse network interfaces (ip link output)
        const INTERFACE_DELIMITER: &str = "------ NETWORK INTERFACES";
        
        if let Some(start_index) = content.find(INTERFACE_DELIMITER) {
            let iface_content = &content[start_index..];
            let lines: Vec<&str> = iface_content
                .lines()
                .skip(1) // Skip the delimiter line itself
                .take_while(|&line| {
                    let trimmed = line.trim();
                    !(trimmed.starts_with("------") && !trimmed.contains(INTERFACE_DELIMITER))
                })
                .collect();

            let mut current_interface: Option<NetworkInterface> = None;
            let mut expecting_rx_stats = false;
            let mut expecting_tx_stats = false;

            for line in lines {
                let trimmed = line.trim();
                
                // Skip empty lines and header lines
                if trimmed.is_empty() || trimmed.starts_with("Inter-") || trimmed.starts_with(" face") {
                    continue;
                }
                
                // Skip lines that start with "link/" (link type lines like "link/ether ...")
                if trimmed.starts_with("link/") {
                    continue;
                }
                
                // Check if this is an interface definition line (format: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...")
                // Pattern: starts with number, colon, space, then interface name, colon, then flags in <>
                if let Some(first_colon) = trimmed.find(':') {
                    // Check if the part before first colon is a number (interface index)
                    let before_first_colon = &trimmed[..first_colon];
                    if before_first_colon.parse::<u32>().is_ok() {
                        // This is an interface definition line: "1: lo: <...>"
                        if let Some(iface) = current_interface.take() {
                            interfaces.push(iface);
                        }
                        expecting_rx_stats = false;
                        expecting_tx_stats = false;

                        // Extract interface name (between first colon and second colon)
                        let after_first_colon = &trimmed[first_colon + 1..];
                        let name = if let Some(second_colon) = after_first_colon.find(':') {
                            after_first_colon[..second_colon].trim().to_string()
                        } else {
                            continue; // Malformed line
                        };

                        let rest = &after_first_colon[after_first_colon.find(':').unwrap() + 1..];
                        let mut flags = Vec::new();
                        let mut mtu = None;
                        let mut ip_addresses = Vec::new();

                        // Parse flags from <FLAG1,FLAG2,...>
                        if let Some(flags_start) = rest.find('<') {
                            if let Some(flags_end) = rest[flags_start + 1..].find('>') {
                                let flags_str = &rest[flags_start + 1..flags_start + 1 + flags_end];
                                flags = flags_str.split(',').map(|s| s.trim().to_string()).collect();
                            }
                        }

                        // Parse MTU (format: "mtu 65536")
                        if let Some(mtu_part) = rest.find("mtu ") {
                            let mtu_str = &rest[mtu_part + 4..];
                            if let Some(end) = mtu_str.find(' ') {
                                mtu = mtu_str[..end].parse().ok();
                            } else {
                                mtu = mtu_str.parse().ok();
                            }
                        }

                        current_interface = Some(NetworkInterface {
                            name,
                            ip_addresses,
                            flags,
                            mtu,
                            rx_bytes: None,
                            tx_bytes: None,
                        });
                        continue;
                    }
                }

                // Handle IP address lines (e.g., "inet 192.168.1.1/24" or "    inet 192.168.1.1/24")
                if let Some(ref mut iface) = current_interface {
                    if trimmed.starts_with("inet ") || trimmed.starts_with("inet6 ") {
                        expecting_rx_stats = false;
                        expecting_tx_stats = false;
                        let ip_part = if trimmed.starts_with("inet6 ") {
                            &trimmed[6..]
                        } else {
                            &trimmed[5..]
                        };
                        if let Some(space_pos) = ip_part.find(' ') {
                            let ip_addr = ip_part[..space_pos].to_string();
                            iface.ip_addresses.push(ip_addr);
                        } else {
                            iface.ip_addresses.push(ip_part.to_string());
                        }
                    }
                    // Handle RX header line: "RX: bytes  packets  errors  dropped overrun mcast"
                    else if trimmed.starts_with("RX:") {
                        expecting_rx_stats = true;
                        expecting_tx_stats = false;
                    }
                    // Handle TX header line: "TX: bytes  packets  errors  dropped carrier collsns"
                    else if trimmed.starts_with("TX:") {
                        expecting_rx_stats = false;
                        expecting_tx_stats = true;
                    }
                    // Handle stats data lines (format: "33478      424      0       0       0       0")
                    // These are whitespace-separated numbers after RX: or TX: headers
                    else if expecting_rx_stats || expecting_tx_stats {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if !parts.is_empty() {
                            // First column is bytes
                            if let Ok(bytes) = parts[0].parse::<u64>() {
                                if expecting_rx_stats {
                                    iface.rx_bytes = Some(bytes);
                                    expecting_rx_stats = false;
                                } else if expecting_tx_stats {
                                    iface.tx_bytes = Some(bytes);
                                    expecting_tx_stats = false;
                                }
                            }
                        }
                    }
                    // Handle RX/TX bytes from ifconfig format (legacy support)
                    else if trimmed.contains("RX bytes:") || trimmed.contains("TX bytes:") {
                        // Parse RX/TX bytes from ifconfig output
                        // Format can be: "        RX bytes:123456789  TX bytes:987654321"
                        // or: "RX bytes:123456789 (123.4 MB)  TX bytes:987654321 (987.6 MB)"
                        if trimmed.contains("RX bytes:") {
                            if let Some(bytes_part) = trimmed.find("RX bytes:") {
                                let bytes_str = &trimmed[bytes_part + 9..];
                                let bytes_str = bytes_str.trim_start();
                                // Find the number, which may be followed by space or other text
                                let num_end = bytes_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(bytes_str.len());
                                if let Ok(bytes) = bytes_str[..num_end].parse::<u64>() {
                                    iface.rx_bytes = Some(bytes);
                                }
                            }
                        }
                        if trimmed.contains("TX bytes:") {
                            if let Some(bytes_part) = trimmed.find("TX bytes:") {
                                let bytes_str = &trimmed[bytes_part + 9..];
                                let bytes_str = bytes_str.trim_start();
                                // Find the number, which may be followed by space or other text
                                let num_end = bytes_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(bytes_str.len());
                                if let Ok(bytes) = bytes_str[..num_end].parse::<u64>() {
                                    iface.tx_bytes = Some(bytes);
                                }
                            }
                        }
                    }
                }
            }

            if let Some(iface) = current_interface {
                interfaces.push(iface);
            }
        }

        // Build result JSON from merged socket map
        if !socket_map.is_empty() {
            let sockets_json: Vec<Value> = socket_map.into_values().map(|s| {
                let mut obj = Map::new();
                obj.insert("protocol".to_string(), json!(s.protocol));
                // Keep combined format for backward compatibility
                obj.insert("local_address".to_string(), json!(s.local_address));
                obj.insert("remote_address".to_string(), json!(s.remote_address));
                // Add separate IP and port fields
                if let Some(ref local_ip) = s.local_ip {
                    obj.insert("local_ip".to_string(), json!(local_ip));
                }
                if let Some(local_port) = s.local_port {
                    obj.insert("local_port".to_string(), json!(local_port));
                }
                if let Some(ref remote_ip) = s.remote_ip {
                    obj.insert("remote_ip".to_string(), json!(remote_ip));
                }
                if let Some(remote_port) = s.remote_port {
                    obj.insert("remote_port".to_string(), json!(remote_port));
                }
                if let Some(state) = s.state {
                    obj.insert("state".to_string(), json!(state));
                }
                if let Some(uid) = s.uid {
                    obj.insert("uid".to_string(), json!(uid));
                }
                if let Some(inode) = s.inode {
                    obj.insert("inode".to_string(), json!(inode));
                }
                if let Some(recv_q) = s.recv_q {
                    obj.insert("recv_q".to_string(), json!(recv_q));
                }
                if let Some(send_q) = s.send_q {
                    obj.insert("send_q".to_string(), json!(send_q));
                }
                if let Some(sk) = s.socket_key {
                    obj.insert("socket_key".to_string(), json!(sk));
                }
                if let Some(additional) = s.additional_info {
                    obj.insert("additional_info".to_string(), json!(additional));
                }
                json!(obj)
            }).collect();
            result.insert("sockets".to_string(), json!(sockets_json));
        }

        if !interfaces.is_empty() {
            let interfaces_json: Vec<Value> = interfaces.into_iter().map(|i| {
                let mut obj = Map::new();
                obj.insert("name".to_string(), json!(i.name));
                obj.insert("ip_addresses".to_string(), json!(i.ip_addresses));
                obj.insert("flags".to_string(), json!(i.flags));
                if let Some(mtu) = i.mtu {
                    obj.insert("mtu".to_string(), json!(mtu));
                }
                if let Some(rx) = i.rx_bytes {
                    obj.insert("rx_bytes".to_string(), json!(rx));
                }
                if let Some(tx) = i.tx_bytes {
                    obj.insert("tx_bytes".to_string(), json!(tx));
                }
                json!(obj)
            }).collect();
            result.insert("interfaces".to_string(), json!(interfaces_json));
        }

        if !network_stats.is_empty() {
            // Aggregate stats by interface (wifi_network_name for WIFI, subscriber_id for MOBILE)
            use std::collections::HashMap;
            let mut aggregated_stats: HashMap<String, NetworkStats> = HashMap::new();
            
            for stat in network_stats {
                // Create a unique key for the interface
                let interface_key = if let Some(ref wifi_name) = stat.wifi_network_name {
                    // For WiFi, use the network name
                    format!("WIFI:{}", wifi_name)
                } else if let Some(ref sub_id) = stat.subscriber_id {
                    // For Mobile, use subscriber ID
                    format!("MOBILE:{}", sub_id)
                } else if let Some(ref net_type) = stat.network_type {
                    // Fallback to network type if no specific identifier
                    format!("{}:unknown", net_type)
                } else {
                    // Skip entries without interface information
                    continue;
                };
                
                // Aggregate stats for the same interface
                if let Some(existing) = aggregated_stats.get_mut(&interface_key) {
                    existing.rx_bytes += stat.rx_bytes;
                    existing.tx_bytes += stat.tx_bytes;
                    existing.rx_packets = Some(
                        existing.rx_packets.unwrap_or(0) + stat.rx_packets.unwrap_or(0)
                    );
                    existing.tx_packets = Some(
                        existing.tx_packets.unwrap_or(0) + stat.tx_packets.unwrap_or(0)
                    );
                    // Keep the first entry's metadata (network_type, metered, default_network, etc.)
                    // These should be the same for all entries with the same interface key
                } else {
                    // First entry for this interface, create a new aggregated entry
                    aggregated_stats.insert(interface_key, stat);
                }
            }
            
            // Convert aggregated stats to JSON (remove uid and package_name from aggregated entries)
            let stats_json: Vec<Value> = aggregated_stats.into_values().map(|s| {
                let mut obj = Map::new();
                // Don't include uid or package_name in aggregated entries
                obj.insert("rx_bytes".to_string(), json!(s.rx_bytes));
                obj.insert("tx_bytes".to_string(), json!(s.tx_bytes));
                if let Some(rx_pkts) = s.rx_packets {
                    obj.insert("rx_packets".to_string(), json!(rx_pkts));
                }
                if let Some(tx_pkts) = s.tx_packets {
                    obj.insert("tx_packets".to_string(), json!(tx_pkts));
                }
                // Add interface information
                if let Some(ref net_type) = s.network_type {
                    obj.insert("network_type".to_string(), json!(net_type));
                }
                if let Some(ref wifi_name) = s.wifi_network_name {
                    obj.insert("wifi_network_name".to_string(), json!(wifi_name));
                }
                if let Some(ref sub_id) = s.subscriber_id {
                    obj.insert("subscriber_id".to_string(), json!(sub_id));
                }
                if let Some(ref rat) = s.rat_type {
                    obj.insert("rat_type".to_string(), json!(rat));
                }
                if let Some(metered) = s.metered {
                    obj.insert("metered".to_string(), json!(metered));
                }
                if let Some(default_net) = s.default_network {
                    obj.insert("default_network".to_string(), json!(default_net));
                }
                json!(obj)
            }).collect();
            result.insert("network_stats".to_string(), json!(stats_json));
        }

        Ok(json!(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_netstat() {
        let data = b"
------ NETSTAT (netstat -npWae) ------
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address                                       Foreign Address                                     State       User       Inode       PID/Program Name
tcp        0      1 192.168.8.183:55191                                 51.116.253.169:443                                  SYN_SENT    1010351    1136844     -
tcp      130      0 192.168.8.183:51360                                 216.239.38.223:443                                  CLOSE_WAIT  1010251    1107231     -
udp        0      0 192.168.8.183:40988                                 62.201.149.82:500                                   ESTABLISHED 1000       1166277     -
------ 0.056s was the duration of 'NETSTAT' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["sockets"].is_array());
        let sockets = result["sockets"].as_array().unwrap();
        assert!(sockets.len() >= 3);
        
        // Find the SYN_SENT socket
        let syn_sent = sockets.iter().find(|s| s["local_address"].as_str() == Some("192.168.8.183:55191")).unwrap();
        assert_eq!(syn_sent["protocol"], "tcp");
        assert_eq!(syn_sent["state"], "SYN_SENT");
        assert_eq!(syn_sent["uid"], 1010351);
        assert_eq!(syn_sent["inode"], 1136844);
        assert_eq!(syn_sent["recv_q"], 0);
        assert_eq!(syn_sent["send_q"], 1);
        // Verify IP and port are extracted separately
        assert_eq!(syn_sent["local_ip"], "192.168.8.183");
        assert_eq!(syn_sent["local_port"], 55191);
        assert_eq!(syn_sent["remote_ip"], "51.116.253.169");
        assert_eq!(syn_sent["remote_port"], 443);
    }

    #[test]
    fn test_parse_network_stats() {
        // Test with actual format from dumpstate.txt
        let data = b"
------ CHECKIN NETSTATS (/system/bin/dumpsys -T 30000 netstats --full --uid) ------
Xt stats:
  Complete history:
  ident=[{type=0, ratType=-2, subscriberId=208202..., metered=false, defaultNetwork=false, oemManaged=OEM_NONE, subId=1}] uid=-1 set=ALL tag=0x0
    NetworkStatsHistory: bucketDuration=3600
      st=1756983600 rb=2526 rp=8 tb=3681 tp=7 op=0
      st=1756987200 rb=1638 rp=3 tb=2535 tp=3 op=0
      st=1756990800 rb=1316 rp=3 tb=2036 tp=3 op=0
Uid stats:
  ident=[{type=1, ratType=COMBINED, wifiNetworkKey=\"Fraise\"wpa2-psk, metered=false, defaultNetwork=true, oemManaged=OEM_NONE, subId=-1}] uid=1005009 set=FOREGROUND tag=0x0
    NetworkStatsHistory: bucketDuration=7200
      st=1758002400 rb=7183 rp=15 tb=3671 tp=16 op=0
      st=1758016800 rb=7297 rp=16 tb=3631 tp=15 op=0
      st=1758031200 rb=7577 rp=16 tb=3927 tp=18 op=0
------ 0.194s was the duration of 'CHECKIN NETSTATS' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["network_stats"].is_array());
        let stats = result["network_stats"].as_array().unwrap();
        assert!(stats.len() >= 2);
        
        // After aggregation, entries are grouped by interface (not by UID)
        // Find stats for MOBILE network (subscriber_id based)
        let mobile_stats: Vec<_> = stats.iter().filter(|s| {
            s["network_type"].as_str() == Some("MOBILE") && s["subscriber_id"].is_string()
        }).collect();
        assert!(mobile_stats.len() >= 1);
        let mobile = mobile_stats[0];
        // Sum of rb values: 2526 + 1638 + 1316 = 5480
        assert_eq!(mobile["rx_bytes"], 5480u64);
        // Sum of tb values: 3681 + 2535 + 2036 = 8252
        assert_eq!(mobile["tx_bytes"], 8252u64);
        // Sum of rp values: 8 + 3 + 3 = 14
        assert_eq!(mobile["rx_packets"], 14u64);
        // Sum of tp values: 7 + 3 + 3 = 13
        assert_eq!(mobile["tx_packets"], 13u64);
        // Verify interface information for MOBILE
        assert_eq!(mobile["network_type"], "MOBILE");
        assert_eq!(mobile["rat_type"], "-2");
        assert_eq!(mobile["metered"], false);
        assert_eq!(mobile["default_network"], false);
        // Aggregated entries should not have uid or package_name
        assert!(!mobile.as_object().unwrap().contains_key("uid"));
        assert!(!mobile.as_object().unwrap().contains_key("package_name"));
        
        // Find stats for WIFI network "Fraise"
        let wifi_stats: Vec<_> = stats.iter().filter(|s| {
            s["network_type"].as_str() == Some("WIFI") && 
            s["wifi_network_name"].as_str() == Some("Fraise")
        }).collect();
        assert!(wifi_stats.len() >= 1);
        let wifi = wifi_stats[0];
        // Sum of rb values: 7183 + 7297 + 7577 = 22057
        assert_eq!(wifi["rx_bytes"], 22057u64);
        // Sum of tb values: 3671 + 3631 + 3927 = 11229
        assert_eq!(wifi["tx_bytes"], 11229u64);
        // Verify interface information for WIFI
        assert_eq!(wifi["network_type"], "WIFI");
        assert_eq!(wifi["wifi_network_name"], "Fraise");
        assert_eq!(wifi["rat_type"], "COMBINED");
        assert_eq!(wifi["metered"], false);
        assert_eq!(wifi["default_network"], true);
        // Aggregated entries should not have uid or package_name
        assert!(!wifi.as_object().unwrap().contains_key("uid"));
        assert!(!wifi.as_object().unwrap().contains_key("package_name"));
    }

    #[test]
    fn test_parse_detailed_socket_state() {
        let data = b"
------ DETAILED SOCKET STATE (ss -eionptu) ------
Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
tcp    SYN-SENT   0      1      192.168.8.183:55191              51.116.253.169:443                 timer:(on,1.484ms,7) uid:1010351 ino:1136844 sk:9087 <->
	 cubic rto:8000 backoff:7 mss:524 rcvmss:88 advmss:1460 cwnd:1 ssthresh:7 segs_out:8 lastsnd:10648180 lastrcv:10648180 lastack:10648180 app_limited unacked:1 retrans:0/7 lost:1
udp    ESTAB      0      0      192.168.8.183:40988              62.201.149.82:500                 uid:1000 ino:1166277 sk:5d1e <->
------ 0.041s was the duration of 'DETAILED SOCKET STATE' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["sockets"].is_array());
        let sockets = result["sockets"].as_array().unwrap();
        assert!(sockets.len() >= 1);
        
        // Find the SYN-SENT socket
        let syn_sent = sockets.iter().find(|s| s["local_address"].as_str() == Some("192.168.8.183:55191")).unwrap();
        assert_eq!(syn_sent["protocol"], "tcp");
        assert_eq!(syn_sent["state"], "SYN-SENT");
        assert_eq!(syn_sent["uid"], 1010351);
        assert_eq!(syn_sent["inode"], 1136844);
        assert_eq!(syn_sent["socket_key"], "9087");
        assert!(syn_sent["additional_info"].as_str().is_some());
    }

    #[test]
    fn test_parse_network_dev_info() {
        let data = b"
------ NETWORK DEV INFO (/proc/net/dev) ------
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   33478     424    0    0    0     0          0         0    33478     424    0    0    0     0       0          0
 wlan0: 128362872  110953    0    0    0     0          0         0 11470306   38427   10    0    0     0       0          0
------ 0.000s was the duration of 'NETWORK DEV INFO' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["interfaces"].is_array());
        let interfaces = result["interfaces"].as_array().unwrap();
        assert!(interfaces.len() >= 2);
        
        // Find wlan0 interface
        let wlan0 = interfaces.iter().find(|i| i["name"].as_str() == Some("wlan0")).unwrap();
        assert_eq!(wlan0["rx_bytes"], 128362872);
        assert_eq!(wlan0["tx_bytes"], 11470306);
    }

    #[test]
    fn test_merge_netstat_and_ss() {
        // Test that NETSTAT and DETAILED SOCKET STATE data is merged correctly
        let data = b"
------ NETSTAT (netstat -npWae) ------
Proto Recv-Q Send-Q Local Address                                       Foreign Address                                     State       User       Inode       PID/Program Name
tcp        0      1 192.168.8.183:55191                                 51.116.253.169:443                                  SYN_SENT    1010351    1136844     -
------ 0.056s was the duration of 'NETSTAT' ------
------ DETAILED SOCKET STATE (ss -eionptu) ------
Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
tcp    SYN-SENT   0      1      192.168.8.183:55191              51.116.253.169:443                 timer:(on,1.484ms,7) uid:1010351 ino:1136844 sk:9087 <->
	 cubic rto:8000 backoff:7 mss:524
------ 0.041s was the duration of 'DETAILED SOCKET STATE' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["sockets"].is_array());
        let sockets = result["sockets"].as_array().unwrap();
        // Should be merged into one socket, not two
        assert_eq!(sockets.len(), 1);
        
        let socket = &sockets[0];
        assert_eq!(socket["protocol"], "tcp");
        assert_eq!(socket["local_address"], "192.168.8.183:55191");
        assert_eq!(socket["remote_address"], "51.116.253.169:443");
        assert_eq!(socket["state"], "SYN_SENT"); // Normalized to use underscore
        assert_eq!(socket["uid"], 1010351);
        assert_eq!(socket["inode"], 1136844);
        // Additional info from ss command should be present
        assert!(socket["additional_info"].as_str().is_some());
        assert!(socket["socket_key"].as_str().is_some());
    }

    #[test]
    fn test_parse_interfaces() {
        // Test with NETWORK DEV INFO which contains interface statistics
        let data = b"
------ NETWORK DEV INFO (/proc/net/dev) ------
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
 wlan0: 128362872  110953    0    0    0     0          0         0 11470306   38427   10    0    0     0       0          0
    lo:   33478     424    0    0    0     0          0         0    33478     424    0    0    0     0       0          0
------ 0.000s was the duration of 'NETWORK DEV INFO' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["interfaces"].is_array());
        let interfaces = result["interfaces"].as_array().unwrap();
        assert!(interfaces.len() >= 2);
        
        let wlan0 = interfaces.iter().find(|i| i["name"].as_str() == Some("wlan0")).unwrap();
        assert_eq!(wlan0["name"], "wlan0");
        assert_eq!(wlan0["rx_bytes"], 128362872);
        assert_eq!(wlan0["tx_bytes"], 11470306);
    }

    #[test]
    fn test_parse_interfaces_ip_link_format() {
        // Test with actual format from dumpstate.txt (ip link show format)
        let data = b"
------ NETWORK INTERFACES (ip link show) ------
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    RX: bytes  packets  errors  dropped overrun mcast   
    33478      424      0       0       0       0       
    TX: bytes  packets  errors  dropped carrier collsns 
    33478      424      0       0       0       0       
16: rmnet2: <NOARP,UP,LOWER_UP> mtu 1354 qdisc prio state UNKNOWN mode DEFAULT group default qlen 1000
    link/none 
    RX: bytes  packets  errors  dropped overrun mcast   
    19625      54       0       0       0       0       
    TX: bytes  packets  errors  dropped carrier collsns 
    102137     172      0       0       0       0       
53: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DORMANT group default qlen 3000
    link/ether 36:81:57:64:18:ad brd ff:ff:ff:ff:ff:ff
    RX: bytes  packets  errors  dropped overrun mcast   
    128363898  110954   0       0       0       0       
    TX: bytes  packets  errors  dropped carrier collsns 
    11470452   38428    10      0       0       0       
------ 0.027s was the duration of 'NETWORK INTERFACES' ------
        ";
        
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result["interfaces"].is_array());
        let interfaces = result["interfaces"].as_array().unwrap();
        assert!(interfaces.len() >= 3);
        
        // Find lo interface
        let lo = interfaces.iter().find(|i| i["name"].as_str() == Some("lo")).unwrap();
        assert_eq!(lo["name"], "lo");
        assert_eq!(lo["mtu"], 65536);
        assert!(lo["flags"].as_array().unwrap().contains(&json!("LOOPBACK")));
        assert_eq!(lo["rx_bytes"], 33478);
        assert_eq!(lo["tx_bytes"], 33478);
        
        // Find rmnet2 interface
        let rmnet2 = interfaces.iter().find(|i| i["name"].as_str() == Some("rmnet2")).unwrap();
        assert_eq!(rmnet2["name"], "rmnet2");
        assert_eq!(rmnet2["mtu"], 1354);
        assert_eq!(rmnet2["rx_bytes"], 19625);
        assert_eq!(rmnet2["tx_bytes"], 102137);
        
        // Find wlan0 interface
        let wlan0 = interfaces.iter().find(|i| i["name"].as_str() == Some("wlan0")).unwrap();
        assert_eq!(wlan0["name"], "wlan0");
        assert_eq!(wlan0["mtu"], 1500);
        assert!(wlan0["flags"].as_array().unwrap().contains(&json!("UP")));
        assert_eq!(wlan0["rx_bytes"], 128363898);
        assert_eq!(wlan0["tx_bytes"], 11470452);
    }

    #[test]
    fn test_parse_empty() {
        let data = b"Some random data without network sections";
        let parser = NetworkParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result.is_object());
        // Empty result should have no arrays
        assert!(!result.as_object().unwrap().contains_key("sockets"));
        assert!(!result.as_object().unwrap().contains_key("interfaces"));
        assert!(!result.as_object().unwrap().contains_key("network_stats"));
    }
}
