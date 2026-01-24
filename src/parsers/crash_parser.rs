use super::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;

// ============================================================================
// TOMBSTONE STRUCTURES (Native Crashes)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BacktraceFrame {
    pub frame: i32,  // -1 for unparsed/raw lines
    pub pc: String,
    pub library: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Tombstone {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub timestamp: String,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub process_name: String,
    pub thread_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub build_fingerprint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub abi: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signal: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fault_addr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub abort_message: String,
    pub backtrace: Vec<BacktraceFrame>,
}

// ============================================================================
// ANR FILE STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnrFile {
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub size: u64,
    pub timestamp: String,  // Formatted as "YYYY-MM-DD HH:MM"
    pub filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnrFiles {
    pub files: Vec<AnrFile>,
    pub total_size: u64,
}

// ============================================================================
// ANR TRACE STRUCTURES (VM TRACES AT LAST ANR)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StackFrame {
    pub frame_type: String,  // "managed" or "native"
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file_loc: String,
    pub line_number: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub library: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thread {
    pub name: String,
    pub priority: u32,
    pub tid: u32,
    pub status: String,
    pub is_daemon: bool,
    pub properties: HashMap<String, String>,
    pub stack_trace: Vec<StackFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnrTrace {
    pub header: HashMap<String, String>,
    pub process_info: HashMap<String, String>,
    pub threads: Vec<Thread>,
}

// ============================================================================
// MAIN CRASH INFO STRUCTURE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CrashInfo {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<Tombstone>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anr_files: Option<AnrFiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anr_trace: Option<AnrTrace>,
}

impl Default for CrashInfo {
    fn default() -> Self {
        Self {
            tombstones: Vec::new(),
            anr_files: None,
            anr_trace: None,
        }
    }
}

impl Default for StackFrame {
    fn default() -> Self {
        Self {
            frame_type: String::new(),
            method: String::new(),
            file_loc: String::new(),
            line_number: 0,
            address: String::new(),
            library: String::new(),
            details: String::new(),
        }
    }
}

impl Default for BacktraceFrame {
    fn default() -> Self {
        Self {
            frame: 0,
            pc: String::new(),
            library: String::new(),
            function: None,
            offset: None,
            build_id: None,
            raw_line: String::new(),
        }
    }
}

impl Default for Tombstone {
    fn default() -> Self {
        Self {
            timestamp: String::new(),
            pid: 0,
            tid: 0,
            uid: 0,
            process_name: String::new(),
            thread_name: String::new(),
            cmdline: String::new(),
            build_fingerprint: String::new(),
            abi: String::new(),
            signal: String::new(),
            code: String::new(),
            fault_addr: String::new(),
            abort_message: String::new(),
            backtrace: Vec::new(),
        }
    }
}

impl Default for AnrFile {
    fn default() -> Self {
        Self {
            permissions: String::new(),
            owner: String::new(),
            group: String::new(),
            size: 0,
            timestamp: String::new(),
            filename: String::new(),
        }
    }
}

impl Default for AnrFiles {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            total_size: 0,
        }
    }
}

impl Default for Thread {
    fn default() -> Self {
        Self {
            name: String::new(),
            priority: 0,
            tid: 0,
            status: String::new(),
            is_daemon: false,
            properties: HashMap::new(),
            stack_trace: Vec::new(),
        }
    }
}

impl Default for AnrTrace {
    fn default() -> Self {
        Self {
            header: HashMap::new(),
            process_info: HashMap::new(),
            threads: Vec::new(),
        }
    }
}

// ============================================================================
// CRASH PARSER IMPLEMENTATION
// ============================================================================

pub struct CrashParser;

impl Default for CrashParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Crash Parser")
    }
}

impl CrashParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(CrashParser)
    }

    // ========================================================================
    // TOMBSTONE PARSING
    // ========================================================================

    fn parse_tombstones(content: &str) -> Vec<Tombstone> {
        let mut tombstones = Vec::new();
        let mut current_tombstone: Option<Tombstone> = None;
        let mut in_backtrace = false;

        for line in content.lines() {
            // Strip logcat prefix first for all checks
            let line_content = Self::strip_logcat_prefix(line);
            
            // Skip empty lines
            if line_content.trim().is_empty() {
                continue;
            }
            
            // Check for tombstone start marker
            if line_content.contains("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***") {
                // Save previous tombstone if exists
                if let Some(tombstone) = current_tombstone.take() {
                    tombstones.push(tombstone);
                }
                // Start new tombstone
                current_tombstone = Some(Tombstone {
                    timestamp: String::new(),
                    pid: 0,
                    tid: 0,
                    uid: 0,
                    process_name: String::new(),
                    thread_name: String::new(),
                    cmdline: String::new(),
                    build_fingerprint: String::new(),
                    abi: String::new(),
                    signal: String::new(),
                    code: String::new(),
                    fault_addr: String::new(),
                    abort_message: String::new(),
                    backtrace: Vec::new(),
                });
                in_backtrace = false;
                continue;
            }

            if let Some(ref mut tombstone) = current_tombstone {
                // Check for backtrace start
                if line_content.starts_with("backtrace:") {
                    in_backtrace = true;
                    continue;
                }
                
                // Parse backtrace frames if we're in backtrace section
                if in_backtrace {
                    if line_content.starts_with("stack:") {
                        in_backtrace = false;
                        continue;
                    }
                    
                    // Skip register dumps
                    if line_content.starts_with("x0 ") || line_content.starts_with("x4 ") ||
                       line_content.starts_with("x8 ") || line_content.starts_with("x12") ||
                       line_content.starts_with("x16") || line_content.starts_with("x20") ||
                       line_content.starts_with("x24") || line_content.starts_with("x28") ||
                       line_content.starts_with("lr ") || line_content.starts_with("sp ") ||
                       line_content.starts_with("pc ") || line_content.starts_with("pst") ||
                       line_content.contains("total frames") {
                        continue;
                    }
                    
                    if let Some(frame) = Self::parse_backtrace_frame(line_content) {
                        tombstone.backtrace.push(frame);
                    } else if !line_content.trim().is_empty() {
                        // Add as unparsed line
                        tombstone.backtrace.push(BacktraceFrame {
                            frame: -1,
                            pc: String::new(),
                            library: String::new(),
                            function: None,
                            offset: None,
                            build_id: None,
                            raw_line: line_content.to_string(),
                        });
                    }
                    continue;
                }
                
                // Parse various tombstone fields
                if line_content.starts_with("Timestamp:") {
                    tombstone.timestamp = line_content
                        .strip_prefix("Timestamp:")
                        .unwrap_or("")
                        .trim()
                        .to_string();
                } else if line_content.starts_with("Build fingerprint:") {
                    tombstone.build_fingerprint = line_content
                        .strip_prefix("Build fingerprint:")
                        .unwrap_or("")
                        .trim()
                        .trim_matches('\'')
                        .to_string();
                } else if line_content.starts_with("ABI:") {
                    tombstone.abi = line_content
                        .strip_prefix("ABI:")
                        .unwrap_or("")
                        .trim()
                        .trim_matches('\'')
                        .to_string();
                } else if line_content.starts_with("Cmdline:") {
                    tombstone.cmdline = line_content
                        .strip_prefix("Cmdline:")
                        .unwrap_or("")
                        .trim()
                        .to_string();
                } else if line_content.starts_with("uid:") {
                    if let Some(uid_str) = line_content.strip_prefix("uid:") {
                        tombstone.uid = uid_str.trim().parse().unwrap_or(0);
                    }
                } else if line_content.starts_with("Abort message:") {
                    tombstone.abort_message = line_content
                        .strip_prefix("Abort message:")
                        .unwrap_or("")
                        .trim()
                        .trim_matches('\'')
                        .to_string();
                } else if line_content.contains("pid:") && line_content.contains("tid:") && line_content.contains(">>>") {
                    // Parse pid/tid/name line: "pid: 5510, tid: 6679, name: thumbThread0  >>> com.sec.android.gallery3d <<<"
                    Self::parse_pid_tid_line(line_content, tombstone);
                } else if line_content.contains("signal ") && line_content.contains("code ") && line_content.contains("fault addr") {
                    // Parse signal line: "signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x00000071661fa000"
                    Self::parse_signal_line(line_content, tombstone);
                }
            }
        }

        // Save last tombstone
        if let Some(tombstone) = current_tombstone {
            tombstones.push(tombstone);
        }

        tombstones
    }

    fn strip_logcat_prefix(line: &str) -> &str {
        // Logcat format: "MM-DD HH:MM:SS.mmm  PID  TID  PID LEVEL TAG : content"
        // Example: "11-08 17:54:04.540 10120  6693  6693 F DEBUG   : *** *** ***"
        
        let trimmed = line.trim();
        
        // Check if line matches logcat pattern
        if trimmed.len() > 40 {
            // Look for the pattern "MM-DD HH:MM:SS"
            let bytes = trimmed.as_bytes();
            if bytes.len() > 18 &&
               bytes[2] == b'-' &&
               bytes[5] == b' ' &&
               bytes[8] == b':' &&
               bytes[11] == b':' {
                // Find the first ': ' after position 20 (after timestamp and PIDs)
                // This should be the separator between TAG and content
                if let Some(pos) = trimmed[20..].find(": ") {
                    return trimmed[20 + pos + 2..].trim();
                }
            }
        }
        
        trimmed
    }

    fn parse_pid_tid_line(line: &str, tombstone: &mut Tombstone) {
        // Format: "pid: 5510, tid: 6679, name: thumbThread0  >>> com.sec.android.gallery3d <<<"
        
        // Extract pid
        if let Some(pid_start) = line.find("pid:") {
            let after_pid = &line[pid_start + 4..];
            if let Some(comma_pos) = after_pid.find(',') {
                let pid_str = after_pid[..comma_pos].trim();
                tombstone.pid = pid_str.parse().unwrap_or(0);
            }
        }

        // Extract tid
        if let Some(tid_start) = line.find("tid:") {
            let after_tid = &line[tid_start + 4..];
            if let Some(comma_pos) = after_tid.find(',') {
                let tid_str = after_tid[..comma_pos].trim();
                tombstone.tid = tid_str.parse().unwrap_or(0);
            }
        }

        // Extract thread name
        if let Some(name_start) = line.find("name:") {
            let after_name = &line[name_start + 5..];
            if let Some(arrow_pos) = after_name.find(">>>") {
                tombstone.thread_name = after_name[..arrow_pos].trim().to_string();
            }
        }

        // Extract process name
        if let Some(start_arrow) = line.find(">>>") {
            let after_arrow = &line[start_arrow + 3..];
            if let Some(end_arrow) = after_arrow.find("<<<") {
                tombstone.process_name = after_arrow[..end_arrow].trim().to_string();
            }
        }
    }

    fn parse_signal_line(line: &str, tombstone: &mut Tombstone) {
        // Format: "signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x00000071661fa000"
        
        // Extract signal
        if let Some(sig_start) = line.find('(') {
            if let Some(sig_end) = line[sig_start..].find(')') {
                tombstone.signal = line[sig_start + 1..sig_start + sig_end].to_string();
            }
        }

        // Extract code
        if let Some(code_start) = line.find("code") {
            let after_code = &line[code_start..];
            if let Some(paren_start) = after_code.find('(') {
                if let Some(paren_end) = after_code[paren_start..].find(')') {
                    tombstone.code = after_code[paren_start + 1..paren_start + paren_end].to_string();
                }
            }
        }

        // Extract fault address
        if let Some(addr_start) = line.find("fault addr") {
            let after_addr = &line[addr_start + 10..].trim();
            tombstone.fault_addr = after_addr.split_whitespace().next().unwrap_or("").to_string();
        }
    }

    fn parse_backtrace_frame(line: &str) -> Option<BacktraceFrame> {
        // Format: "#00 pc 00000000001de20c  /system/lib64/libimagecodec.quram.so (QuramDngOpcodeScalePerColumn::processArea(QuramDngDecoder&, QuramDngImage*, QuramDngRect*)+552) (BuildId: 995700b69e2632866b44243e378997c680105a42)"
        
        let trimmed = line.trim();
        
        // Must start with #NN
        if !trimmed.starts_with('#') {
            return None;
        }

        // Must contain "pc"
        if !trimmed.contains(" pc ") {
            return None;
        }

        let parts: Vec<&str> = trimmed.splitn(4, ' ').collect();
        if parts.len() < 4 {
            return None;
        }

        // Parse frame number
        let frame_num = parts[0]
            .trim_start_matches('#')
            .parse::<i32>()
            .ok()?;

        // parts[1] should be "pc"
        if parts[1] != "pc" {
            return None;
        }

        // Parse PC address
        let pc = parts[2].to_string();

        // Parse library and optional function/build_id
        let rest = parts[3];
        
        let (library, function, offset, build_id) = Self::parse_frame_details(rest);

        Some(BacktraceFrame {
            frame: frame_num,
            pc,
            library,
            function,
            offset,
            build_id,
            raw_line: trimmed.to_string(),
        })
    }

    fn parse_frame_details(rest: &str) -> (String, Option<String>, Option<String>, Option<String>) {
        let mut function = None;
        let mut offset = None;
        let mut build_id = None;

        // Split by first parenthesis to separate library from function
        let library = if let Some(first_paren) = rest.find('(') {
            let lib = rest[..first_paren].trim().to_string();
            
            // Everything after is either function info or BuildId
            let after_paren = &rest[first_paren + 1..];
            
            // Check for BuildId at the end
            if let Some(build_id_start) = after_paren.rfind("(BuildId: ") {
                let before_build_id = &after_paren[..build_id_start];
                let build_id_part = &after_paren[build_id_start + 10..];
                
                if let Some(close_paren) = build_id_part.find(')') {
                    build_id = Some(build_id_part[..close_paren].trim().to_string());
                }
                
                // Parse function from before_build_id
                if let Some(close_paren) = before_build_id.rfind(')') {
                    let func_info = before_build_id[..close_paren].trim();
                    
                    // Check for offset (e.g., "functionName+552")
                    if let Some(plus_pos) = func_info.rfind('+') {
                        function = Some(func_info[..plus_pos].to_string());
                        offset = Some(func_info[plus_pos + 1..].to_string());
                    } else {
                        function = Some(func_info.to_string());
                    }
                }
            } else {
                // No BuildId, just parse function
                if let Some(close_paren) = after_paren.find(')') {
                    let func_info = after_paren[..close_paren].trim();
                    
                    if let Some(plus_pos) = func_info.rfind('+') {
                        function = Some(func_info[..plus_pos].to_string());
                        offset = Some(func_info[plus_pos + 1..].to_string());
                    } else {
                        function = Some(func_info.to_string());
                    }
                }
            }
            
            lib
        } else {
            // No parentheses, just library
            rest.trim().to_string()
        };

        (library, function, offset, build_id)
    }

    // ========================================================================
    // ANR FILES PARSING
    // ========================================================================

    fn parse_anr_files(content: &str) -> Option<AnrFiles> {
        // Find the ANR FILES section
        let start_marker = "------ ANR FILES";

        let start_idx = content.find(start_marker)?;
        let section = &content[start_idx..];
        
        // Find the end of this section (next ------ marker)
        let lines: Vec<&str> = section.lines().collect();
        let mut data_lines = Vec::new();
        let mut found_start = false;
        
        for line in lines.iter() {
            if !found_start {
                if line.contains(start_marker) {
                    found_start = true;
                }
                continue;
            }
            
            if line.trim().starts_with("------") && !line.contains("ANR FILES") {
                break;
            }
            
            data_lines.push(*line);
        }

        let mut files = Vec::new();
        let mut total_size = 0u64;

        for line in data_lines {
            let trimmed = line.trim();
            
            // Parse "total NNNN" line
            if trimmed.starts_with("total ") {
                if let Some(size_str) = trimmed.strip_prefix("total ") {
                    total_size = size_str.trim().parse().unwrap_or(0);
                }
                continue;
            }

            // Parse file lines (ls -lt format)
            // Example: "-rw------- 1 system system 45768 2025-04-25 13:41 anr_2025-04-25-13-41-55-543"
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            
            if parts.len() >= 8 &&
               (parts[0].starts_with('-') || parts[0].starts_with('d')) {
                
                let permissions = parts[0].to_string();
                let owner = parts[2].to_string();
                let group = parts[3].to_string();
                let size: u64 = parts[4].parse().unwrap_or(0);
                let date = parts[5].to_string();
                let time = parts[6].to_string();
                let filename = parts[7..].join(" ");

                let timestamp = format!("{} {}", date, time);

                files.push(AnrFile {
                    permissions,
                    owner,
                    group,
                    size,
                    timestamp,
                    filename,
                });
            }
        }

        if files.is_empty() {
            None
        } else {
            Some(AnrFiles { files, total_size })
        }
    }

    // ========================================================================
    // ANR TRACE PARSING (VM TRACES AT LAST ANR)
    // ========================================================================

    fn parse_anr_trace(content: &str) -> Option<AnrTrace> {
        let start_marker = "------ VM TRACES AT LAST ANR";
        let end_marker = "----- end";

        let start_idx = content.find(start_marker)?;
        let section_start = start_idx + start_marker.len();
        
        let section = &content[section_start..];
        let end_idx = section.find(end_marker)?;
        let anr_content = &section[..end_idx];

        let mut trace = AnrTrace {
            header: HashMap::new(),
            process_info: HashMap::new(),
            threads: Vec::new(),
        };

        let lines: Vec<&str> = anr_content.lines().collect();
        let mut i = 0;
        let mut current_thread: Option<Thread> = None;

        while i < lines.len() {
            let line = lines[i].trim();

            // Parse header fields
            if line.starts_with("Subject:") {
                if let Some(value) = line.strip_prefix("Subject:") {
                    trace.header.insert("subject".to_string(), value.trim().to_string());
                }
            } else if line.contains(':') &&
                      !line.contains("pid") &&
                      !line.starts_with('|') &&
                      !line.starts_with("at ") &&
                      !line.starts_with("native:") &&
                      !line.starts_with('-') &&
                      !line.starts_with('"') {
                // Generic key:value header
                if let Some((key, value)) = line.split_once(':') {
                    let clean_key = key.trim().to_lowercase().replace(' ', "_");
                    trace.header.insert(clean_key, value.trim().to_string());
                }
            }

            // Parse process info
            if line.starts_with("----- pid") {
                // Format: "----- pid 12345 at 2025-03-28 10:30:45 -----"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(pid) = parts[2].parse::<u32>() {
                        trace.process_info.insert("pid".to_string(), pid.to_string());
                    }
                    if parts.len() >= 6 {
                        let timestamp = format!("{} {}", parts[4], parts[5]);
                        trace.process_info.insert("timestamp".to_string(), timestamp);
                    }
                }
            } else if line.starts_with("Cmd line:") {
                if let Some(value) = line.strip_prefix("Cmd line:") {
                    trace.process_info.insert("cmd_line".to_string(), value.trim().to_string());
                }
            } else if line.starts_with("Build fingerprint:") {
                if let Some(value) = line.strip_prefix("Build fingerprint:") {
                    trace.process_info.insert("build_fingerprint".to_string(), value.trim().trim_matches('\'').to_string());
                }
            } else if line.starts_with("ABI:") {
                if let Some(value) = line.strip_prefix("ABI:") {
                    trace.process_info.insert("abi".to_string(), value.trim().trim_matches('\'').to_string());
                }
            }

            // Parse thread start
            if line.starts_with('"') {
                // Save previous thread
                if let Some(thread) = current_thread.take() {
                    trace.threads.push(thread);
                }

                // Parse thread header
                current_thread = Self::parse_thread_header(line);
            } else if let Some(ref mut thread) = current_thread {
                // Parse thread properties (lines starting with |)
                if line.starts_with('|') {
                    Self::parse_thread_property(line, thread);
                }
                // Parse managed stack frame (starts with "at ")
                else if line.starts_with("at ") {
                    if let Some(frame) = Self::parse_managed_frame(line) {
                        thread.stack_trace.push(frame);
                    }
                }
                // Parse native stack trace
                else if line.starts_with("native:") {
                    // Parse all consecutive native frames
                    let mut j = i;
                    while j < lines.len() {
                        let native_line = lines[j].trim();
                        if !native_line.starts_with("native:") {
                            break;
                        }
                        
                        let frame_content = native_line.strip_prefix("native:").unwrap_or(native_line).trim();
                        if let Some(frame) = Self::parse_native_frame(frame_content) {
                            thread.stack_trace.push(frame);
                        }
                        j += 1;
                    }
                    i = j - 1;
                }
                // Parse held mutexes
                else if line.contains("held mutexes=") {
                    Self::parse_thread_property(&format!("| {}", line), thread);
                }
            }

            i += 1;
        }

        // Save last thread
        if let Some(thread) = current_thread {
            trace.threads.push(thread);
        }

        if trace.threads.is_empty() && trace.header.is_empty() {
            None
        } else {
            Some(trace)
        }
    }

    fn parse_thread_header(line: &str) -> Option<Thread> {
        // Format: "ThreadName" daemon prio=5 tid=123 STATUS
        // Example: "main" prio=5 tid=1 Native
        
        let mut name = String::new();
        let mut priority = 0;
        let mut tid = 0;
        let mut status = String::new();
        let mut is_daemon = false;

        // Extract thread name (quoted string)
        if let Some(end_quote) = line[1..].find('"') {
            name = line[1..=end_quote].to_string();
            let rest = &line[end_quote + 2..];
            
            is_daemon = rest.contains("daemon");
            
            // Parse prio=N
            if let Some(prio_start) = rest.find("prio=") {
                let after_prio = &rest[prio_start + 5..];
                if let Some(space_pos) = after_prio.find(' ') {
                    priority = after_prio[..space_pos].parse().unwrap_or(0);
                }
            }
            
            // Parse tid=N
            if let Some(tid_start) = rest.find("tid=") {
                let after_tid = &rest[tid_start + 4..];
                if let Some(space_pos) = after_tid.find(' ') {
                    tid = after_tid[..space_pos].parse().unwrap_or(0);
                } else {
                    tid = after_tid.trim().parse().unwrap_or(0);
                }
            }
            
            // Status is everything after tid
            if let Some(tid_start) = rest.find("tid=") {
                let after_tid = &rest[tid_start + 4..];
                if let Some(space_pos) = after_tid.find(' ') {
                    status = after_tid[space_pos..].trim().to_string();
                }
            }
        }

        Some(Thread {
            name,
            priority,
            tid,
            status,
            is_daemon,
            properties: HashMap::new(),
            stack_trace: Vec::new(),
        })
    }

    fn parse_thread_property(line: &str, thread: &mut Thread) {
        // Format: "| property=value property2=value2"
        let content = line.trim_start_matches('|').trim();
        
        // Split by spaces, but handle quoted values
        for part in content.split('|') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                thread.properties.insert(key.to_string(), value.to_string());
            }
        }
    }

    fn parse_managed_frame(line: &str) -> Option<StackFrame> {
        // Format: "at com.example.Class.method(File.java:123)"
        let method = line.strip_prefix("at ")?.trim().to_string();
        
        let mut file_loc = String::new();
        let mut line_number = 0;

        // Extract file location and line number from parentheses
        if let Some(paren_start) = method.rfind('(') {
            if let Some(paren_end) = method.rfind(')') {
                let location = &method[paren_start + 1..paren_end];
                
                if let Some(colon_pos) = location.rfind(':') {
                    file_loc = location[..colon_pos].to_string();
                    if let Ok(num) = location[colon_pos + 1..].parse() {
                        line_number = num;
                    }
                } else {
                    file_loc = location.to_string();
                }
            }
        }

        Some(StackFrame {
            frame_type: "managed".to_string(),
            method,
            file_loc,
            line_number,
            address: String::new(),
            library: String::new(),
            details: String::new(),
        })
    }

    fn parse_native_frame(line: &str) -> Option<StackFrame> {
        // Format: "#02 pc 00000000000c9ebc  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start(void*)+204)"
        
        if !line.contains(" pc ") {
            return None;
        }

        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 {
            return None;
        }

        let address = parts[2].to_string();
        let rest = parts[3];

        let (library, details) = if let Some(paren_start) = rest.find('(') {
            let lib = rest[..paren_start].trim().to_string();
            let det = if let Some(paren_end) = rest.rfind(')') {
                rest[paren_start + 1..paren_end].to_string()
            } else {
                String::new()
            };
            (lib, det)
        } else {
            (rest.trim().to_string(), String::new())
        };

        Some(StackFrame {
            frame_type: "native".to_string(),
            method: String::new(),
            file_loc: String::new(),
            line_number: 0,
            address,
            library,
            details,
        })
    }
}

// ============================================================================
// PARSER TRAIT IMPLEMENTATION
// ============================================================================

impl Parser for CrashParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        
        let crash_info = CrashInfo {
            tombstones: Self::parse_tombstones(&content),
            anr_files: Self::parse_anr_files(&content),
            anr_trace: Self::parse_anr_trace(&content),
        };
        
        Ok(serde_json::to_value(crash_info)?)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_CRASH_LOG: &str = r#"
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : Build fingerprint: 'samsung/xxx/release-keys'
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : Revision: '6'
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : ABI: 'arm64'
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : Processor: '4'
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : Timestamp: 2025-11-08 17:54:03.791102828+0100
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : Process uptime: 309s
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : Cmdline: com.sec.android.gallery3d
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : pid: 5510, tid: 6679, name: thumbThread0  >>> com.sec.android.gallery3d <<<
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : uid: 10120
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x00000071661fa000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x0  0000000000000002  x1  0000000000000000  x2  0000000000000002  x3  0000000000000000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x4  b4000071c244125c  x5  0000000000000002  x6  0000000000000000  x7  00000000000407f4
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x8  0000000080000000  x9  0000000000000003  x10 0000000000000001  x11 000000007ffffffe
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x12 b4000073661fa000  x13 0000000000000004  x14 0000000000000001  x15 0000000000000000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x16 0000000037800080  x17 00000000477fff00  x18 0000006ff3f40000  x19 0000000000000000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x20 0000000000000000  x21 0000000000000000  x22 b4000071661fa000  x23 0000000000000000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x24 0000000000000000  x25 000000000000024b  x26 00000070168d5ff8  x27 00000000000fc000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     x28 00000000000fe000  x29 00000070168d5be0
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :     lr  0000006ff5431058  sp  00000070168d5be0  pc  0000006ff543120c  pst 0000000080001000
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : 4 total frames
11-08 17:54:04.540 10120  6693  6693 F DEBUG   : backtrace:
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :       #00 pc 00000000001de20c  /system/lib64/libimagecodec.quram.so (QuramDngOpcodeScalePerColumn::processArea(QuramDngDecoder&, QuramDngImage*, QuramDngRect*)+552) (BuildId: 995700b69e2632866b44243e378997c680105a42)
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :       #01 pc 00000000001f1324  /system/lib64/libimagecodec.quram.so (inplaceOpcodeTask(void*)+32) (BuildId: 995700b69e2632866b44243e378997c680105a42)
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :       #02 pc 00000000000c9ebc  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start(void*)+204) (BuildId: 5f89913e15aa7088d03682fa8322b310)
11-08 17:54:04.540 10120  6693  6693 F DEBUG   :       #03 pc 000000000005dc60  /apex/com.android.runtime/lib64/bionic/libc.so (__start_thread+64) (BuildId: 5f89913e15aa7088d03682fa8322b310)
"#;

    #[test]
    fn test_strip_logcat_prefix() {
        let line = "11-08 17:54:04.540 10120  6693  6693 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***";
        let stripped = CrashParser::strip_logcat_prefix(line);
        assert_eq!(stripped, "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
        
        let line2 = "11-08 17:54:04.540 10120  6693  6693 F DEBUG   : pid: 5510, tid: 6679, name: thumbThread0  >>> com.sec.android.gallery3d <<<";
        let stripped2 = CrashParser::strip_logcat_prefix(line2);
        assert_eq!(stripped2, "pid: 5510, tid: 6679, name: thumbThread0  >>> com.sec.android.gallery3d <<<");
    }

    #[test]
    fn test_parse_backtrace_frame() {
        let line = "#00 pc 00000000001de20c  /system/lib64/libimagecodec.quram.so (QuramDngOpcodeScalePerColumn::processArea(QuramDngDecoder&, QuramDngImage*, QuramDngRect*)+552) (BuildId: 995700b69e2632866b44243e378997c680105a42)";
        
        let frame = CrashParser::parse_backtrace_frame(line).unwrap();
        
        assert_eq!(frame.frame, 0);
        assert_eq!(frame.pc, "00000000001de20c");
        assert_eq!(frame.library, "/system/lib64/libimagecodec.quram.so");
        assert_eq!(frame.function.as_ref().unwrap(), "QuramDngOpcodeScalePerColumn::processArea(QuramDngDecoder&, QuramDngImage*, QuramDngRect*)");
        assert_eq!(frame.offset.as_ref().unwrap(), "552");
        assert_eq!(frame.build_id.as_ref().unwrap(), "995700b69e2632866b44243e378997c680105a42");
    }

    #[test]
    fn test_parse_backtrace_frame_without_function() {
        let line = "#00 pc 0000000000001234  /system/lib64/test.so";
        let frame = CrashParser::parse_backtrace_frame(line).unwrap();
        
        assert_eq!(frame.frame, 0);
        assert_eq!(frame.pc, "0000000000001234");
        assert_eq!(frame.library, "/system/lib64/test.so");
        assert!(frame.function.is_none());
        assert!(frame.offset.is_none());
        assert!(frame.build_id.is_none());
    }

    #[test]
    fn test_parse_backtrace_frame_with_function_no_offset() {
        let line = "#01 pc 0000000000005678  /system/lib64/test.so (testFunction)";
        let frame = CrashParser::parse_backtrace_frame(line).unwrap();
        
        assert_eq!(frame.frame, 1);
        assert_eq!(frame.function.as_ref().unwrap(), "testFunction");
        assert!(frame.offset.is_none());
    }

    #[test]
    fn test_parse_tombstone_basic() {
        let content = r#"
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'samsung/xxx/release-keys'
ABI: 'arm64'
Timestamp: 2025-11-08 17:54:03.791102828+0100
Cmdline: com.sec.android.gallery3d
pid: 5510, tid: 6679, name: thumbThread0  >>> com.sec.android.gallery3d <<<
uid: 10120
signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x00000071661fa000
backtrace:
      #00 pc 00000000001de20c  /system/lib64/libimagecodec.quram.so (QuramDngOpcodeScalePerColumn::processArea(QuramDngDecoder&, QuramDngImage*, QuramDngRect*)+552) (BuildId: 995700b69e2632866b44243e378997c680105a42)
        "#;

        let tombstones = CrashParser::parse_tombstones(content);
        assert_eq!(tombstones.len(), 1);
        
        let t = &tombstones[0];
        assert_eq!(t.pid, 5510);
        assert_eq!(t.tid, 6679);
        assert_eq!(t.uid, 10120);
        assert_eq!(t.thread_name, "thumbThread0");
        assert_eq!(t.process_name, "com.sec.android.gallery3d");
        assert_eq!(t.signal, "SIGSEGV");
        assert_eq!(t.code, "SEGV_ACCERR");
        assert_eq!(t.abi, "arm64");
        assert_eq!(t.backtrace.len(), 1);
        assert_eq!(t.backtrace[0].frame, 0);
    }

    #[test]
    fn test_parse_real_crash_full() {
        let parser = CrashParser::new().unwrap();
        let result = parser.parse(REAL_CRASH_LOG.as_bytes()).unwrap();
        
        let crash_info: CrashInfo = serde_json::from_value(result).unwrap();
        
        // Verify tombstones were parsed
        assert_eq!(crash_info.tombstones.len(), 1);
        
        let tombstone = &crash_info.tombstones[0];
        
        // Check basic fields
        assert_eq!(tombstone.pid, 5510);
        assert_eq!(tombstone.tid, 6679);
        assert_eq!(tombstone.uid, 10120);
        assert_eq!(tombstone.thread_name, "thumbThread0");
        assert_eq!(tombstone.process_name, "com.sec.android.gallery3d");
        assert_eq!(tombstone.cmdline, "com.sec.android.gallery3d");
        
        // Check crash details
        assert_eq!(tombstone.signal, "SIGSEGV");
        assert_eq!(tombstone.code, "SEGV_ACCERR");
        assert_eq!(tombstone.fault_addr, "0x00000071661fa000");
        assert_eq!(tombstone.abi, "arm64");
        assert!(tombstone.build_fingerprint.contains("samsung"));
        assert!(tombstone.timestamp.contains("2025-11-08"));
        
        // Check backtrace
        assert_eq!(tombstone.backtrace.len(), 4);
        
        // Verify frame 0
        let frame0 = &tombstone.backtrace[0];
        assert_eq!(frame0.frame, 0);
        assert_eq!(frame0.pc, "00000000001de20c");
        assert_eq!(frame0.library, "/system/lib64/libimagecodec.quram.so");
        assert_eq!(frame0.function.as_ref().unwrap(), "QuramDngOpcodeScalePerColumn::processArea(QuramDngDecoder&, QuramDngImage*, QuramDngRect*)");
        assert_eq!(frame0.offset.as_ref().unwrap(), "552");
        assert_eq!(frame0.build_id.as_ref().unwrap(), "995700b69e2632866b44243e378997c680105a42");
        
        // Verify frame 2
        let frame2 = &tombstone.backtrace[2];
        assert_eq!(frame2.frame, 2);
        assert_eq!(frame2.library, "/apex/com.android.runtime/lib64/bionic/libc.so");
        assert_eq!(frame2.function.as_ref().unwrap(), "__pthread_start(void*)");
        assert_eq!(frame2.offset.as_ref().unwrap(), "204");
    }

    #[test]
    fn test_parse_anr_files_section() {
        let content = r#"
------ ANR FILES (/data/anr) ------
total 892
-rw------- 1 system system 45768 2025-04-25 13:41 anr_2025-04-25-13-41-55-543
-rw------- 1 system system 32145 2025-04-24 10:30 anr_2025-04-24-10-30-12-123
-rw------- 1 system system 28900 2025-04-23 08:15 anr_2025-04-23-08-15-33-789
------ NEXT SECTION ------
        "#;

        let parser = CrashParser::new().unwrap();
        let result = parser.parse(content.as_bytes()).unwrap();
        let crash_info: CrashInfo = serde_json::from_value(result).unwrap();
        
        assert!(crash_info.anr_files.is_some());
        let anr_files = crash_info.anr_files.unwrap();
        
        assert_eq!(anr_files.total_size, 892);
        assert_eq!(anr_files.files.len(), 3);
        
        // Check first file
        let file0 = &anr_files.files[0];
        assert_eq!(file0.permissions, "-rw-------");
        assert_eq!(file0.owner, "system");
        assert_eq!(file0.group, "system");
        assert_eq!(file0.size, 45768);
        assert_eq!(file0.timestamp, "2025-04-25 13:41");
        assert_eq!(file0.filename, "anr_2025-04-25-13-41-55-543");
    }

    #[test]
    fn test_parse_anr_trace_section() {
        let content = r#"
------ VM TRACES AT LAST ANR (/data/anr/anr_2025-03-28-10-30-45-543) ------
Subject: ANR in com.example.app (com.example.app/.MainActivity)
ProcRank: 0
----- pid 12345 at 2025-03-28 10:30:45 -----
Cmd line: com.example.app
Build fingerprint: 'google/xxx/release-keys'
ABI: 'arm64'

"main" prio=5 tid=1 Native
  | group="main" sCount=1 dsCount=0 flags=1 obj=0x72f12a98 self=0xb400007e00001e50
  | sysTid=12345 nice=0 cgrp=default sched=0/0 handle=0x7ff1234567
  | state=S schedstat=( 1234567890 987654321 1234 ) utm=123 stm=45 core=2 HZ=100
  | stack=0x7fff1234000-0x7fff1236000 stackSize=8188KB
  | held mutexes=
  at java.lang.Object.wait(Native Method)
  at java.lang.Object.wait(Object.java:442)
  at com.example.app.MainActivity.onCreate(MainActivity.java:25)

"Thread-2" daemon prio=5 tid=15 Runnable
  | group="main" sCount=0 dsCount=0 flags=0 obj=0x12f45678 self=0xb400007e12345678
  | sysTid=12360 nice=0 cgrp=default sched=0/0 handle=0x7f89abcdef
  at com.example.app.BackgroundTask.run(BackgroundTask.java:50)

"GC" daemon prio=10 tid=3 Native
  | group="system" sCount=1 dsCount=0 flags=1 obj=0x12345678 self=0xb400007e87654321
  native: #00 pc 00000000000c9ebc  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start(void*)+204) (BuildId: 5f89913e15aa7088d03682fa8322b310)
  native: #01 pc 000000000005dc60  /apex/com.android.runtime/lib64/bionic/libc.so (__start_thread+64) (BuildId: 5f89913e15aa7088d03682fa8322b310)

----- end 12345 -----
        "#;

        let parser = CrashParser::new().unwrap();
        let result = parser.parse(content.as_bytes()).unwrap();
        let crash_info: CrashInfo = serde_json::from_value(result).unwrap();
        
        assert!(crash_info.anr_trace.is_some());
        let trace = crash_info.anr_trace.unwrap();
        
        // Check header
        assert_eq!(trace.header.get("subject").unwrap(), "ANR in com.example.app (com.example.app/.MainActivity)");
        
        // Check process info
        assert_eq!(trace.process_info.get("pid").unwrap(), "12345");
        assert_eq!(trace.process_info.get("cmd_line").unwrap(), "com.example.app");
        assert_eq!(trace.process_info.get("abi").unwrap(), "arm64");
        
        // Check threads
        assert_eq!(trace.threads.len(), 3);
        
        // Check main thread
        let main_thread = &trace.threads[0];
        assert_eq!(main_thread.name, "main");
        assert_eq!(main_thread.priority, 5);
        assert_eq!(main_thread.tid, 1);
        assert_eq!(main_thread.status, "Native");
        assert!(!main_thread.is_daemon);
        assert!(main_thread.properties.contains_key("group"));
        assert_eq!(main_thread.stack_trace.len(), 3);
        
        // Check managed frame
        let managed_frame = &main_thread.stack_trace[2];
        assert_eq!(managed_frame.frame_type, "managed");
        assert!(managed_frame.method.contains("MainActivity.onCreate"));
        assert_eq!(managed_frame.file_loc, "MainActivity.java");
        assert_eq!(managed_frame.line_number, 25);
        
        // Check daemon thread
        let daemon_thread = &trace.threads[1];
        assert_eq!(daemon_thread.name, "Thread-2");
        assert!(daemon_thread.is_daemon);
        assert_eq!(daemon_thread.tid, 15);
        assert_eq!(daemon_thread.status, "Runnable");
        
        // Check GC thread with native frames
        let gc_thread = &trace.threads[2];
        assert_eq!(gc_thread.name, "GC");
        assert!(gc_thread.is_daemon);
        assert_eq!(gc_thread.stack_trace.len(), 2);
        
        // Check native frame
        let native_frame = &gc_thread.stack_trace[0];
        assert_eq!(native_frame.frame_type, "native");
        assert_eq!(native_frame.address, "00000000000c9ebc");
        assert!(native_frame.library.contains("libc.so"));
        assert!(native_frame.details.contains("__pthread_start"));
    }

    #[test]
    fn test_parse_multiple_tombstones() {
        let content = r#"
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'test1'
ABI: 'arm64'
pid: 1000, tid: 1001, name: Thread1  >>> com.test.app1 <<<
uid: 10100
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000000
backtrace:
      #00 pc 0000000000001234  /system/lib64/test.so

*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'test2'
ABI: 'arm'
pid: 2000, tid: 2001, name: Thread2  >>> com.test.app2 <<<
uid: 10200
signal 6 (SIGABRT), code -1 (SI_QUEUE), fault addr 0x00000000000007d0
Abort message: 'Test abort message'
backtrace:
      #00 pc 0000000000005678  /system/lib/test2.so (abort+10)
        "#;

        let parser = CrashParser::new().unwrap();
        let result = parser.parse(content.as_bytes()).unwrap();
        let crash_info: CrashInfo = serde_json::from_value(result).unwrap();
        
        assert_eq!(crash_info.tombstones.len(), 2);
        
        // Check first crash
        assert_eq!(crash_info.tombstones[0].pid, 1000);
        assert_eq!(crash_info.tombstones[0].process_name, "com.test.app1");
        assert_eq!(crash_info.tombstones[0].signal, "SIGSEGV");
        
        // Check second crash
        assert_eq!(crash_info.tombstones[1].pid, 2000);
        assert_eq!(crash_info.tombstones[1].process_name, "com.test.app2");
        assert_eq!(crash_info.tombstones[1].signal, "SIGABRT");
        assert_eq!(crash_info.tombstones[1].abort_message, "Test abort message");
    }

    #[test]
    fn test_empty_input() {
        let parser = CrashParser::new().unwrap();
        let result = parser.parse(b"").unwrap();
        let crash_info: CrashInfo = serde_json::from_value(result).unwrap();
        
        assert!(crash_info.tombstones.is_empty());
        assert!(crash_info.anr_files.is_none());
        assert!(crash_info.anr_trace.is_none());
    }

    #[test]
    fn test_no_crash_data() {
        let content = "This is just random text with no crash information.";
        let parser = CrashParser::new().unwrap();
        let result = parser.parse(content.as_bytes()).unwrap();
        let crash_info: CrashInfo = serde_json::from_value(result).unwrap();
        
        assert!(crash_info.tombstones.is_empty());
        assert!(crash_info.anr_files.is_none());
        assert!(crash_info.anr_trace.is_none());
    }

    #[test]
    fn test_parse_managed_frame() {
        let line = "at com.example.MyClass.doSomething(MyClass.java:123)";
        let frame = CrashParser::parse_managed_frame(line).unwrap();
        
        assert_eq!(frame.frame_type, "managed");
        assert_eq!(frame.file_loc, "MyClass.java");
        assert_eq!(frame.line_number, 123);
        assert!(frame.method.contains("doSomething"));
    }

    #[test]
    fn test_parse_native_frame() {
        let line = "#02 pc 00000000000c9ebc  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start(void*)+204)";
        let frame = CrashParser::parse_native_frame(line).unwrap();
        
        assert_eq!(frame.frame_type, "native");
        assert_eq!(frame.address, "00000000000c9ebc");
        assert_eq!(frame.library, "/apex/com.android.runtime/lib64/bionic/libc.so");
        assert_eq!(frame.details, "__pthread_start(void*)+204");
    }

    #[test]
    fn test_json_serialization() {
        let parser = CrashParser::new().unwrap();
        let result = parser.parse(REAL_CRASH_LOG.as_bytes()).unwrap();
        
        // Verify it can be serialized to JSON
        let json_str = serde_json::to_string_pretty(&result).unwrap();
        assert!(json_str.contains("tombstones"));
        assert!(json_str.contains("SIGSEGV"));
        assert!(json_str.contains("com.sec.android.gallery3d"));
        
        // Verify it can be deserialized back
        let _: CrashInfo = serde_json::from_str(&json_str).unwrap();
    }
}