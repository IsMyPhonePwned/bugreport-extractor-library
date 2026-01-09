use crate::parsers::crash_parser::{CrashInfo, Tombstone, BacktraceFrame, AnrTrace, Thread};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// MEMORY AND REGISTER ANALYSIS STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnalysis {
    pub is_null_deref: bool,
    pub is_heap_spray: bool,
    pub is_stack_pivot: bool,
    pub is_rop_chain_likely: bool,
    pub is_kernel_space: bool,
    pub address_type: String,  // "null", "heap", "stack", "code", "kernel", "unknown"
    pub exploitation_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAnalysis {
    pub pc_suspicious: bool,
    pub sp_suspicious: bool,
    pub lr_suspicious: bool,
    pub register_patterns: Vec<String>,
    pub corruption_detected: bool,
    pub registers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnrEvent {
    pub event_type: String,
    pub severity: Severity,
    pub pid: u32,
    pub process_name: String,
    pub anr_type: String,  // "deadlock", "resource_exhaustion", "infinite_loop", "suspicious_native"
    pub blocked_threads: usize,
    pub main_thread_blocked: bool,
    pub indicators: Vec<String>,
    pub exploitation_likelihood: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadlock_details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious_native_code: Option<String>,
    pub mitigation_recommendations: Vec<String>,
}

// ============================================================================
// DETECTION TYPES AND SEVERITY
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousCrashEvent {
    pub event_type: String,
    pub severity: Severity,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub process_name: String,
    pub thread_name: String,
    pub signal: String,
    pub crash_reason: String,
    pub indicators: Vec<String>,
    pub exploitation_likelihood: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious_library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerable_function: Option<String>,
    pub mitigation_recommendations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_analysis: Option<MemoryAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_analysis: Option<RegisterAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub total_crashes: usize,
    pub suspicious_crashes: usize,
    pub total_anrs: usize,
    pub suspicious_anrs: usize,
    pub events: Vec<SuspiciousCrashEvent>,
    pub anr_events: Vec<AnrEvent>,
    pub summary: DetectionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub most_targeted_processes: Vec<String>,
    pub most_exploited_libraries: Vec<String>,
    pub exploitation_patterns: Vec<String>,
}

// ============================================================================
// SUSPICIOUS INDICATORS
// ============================================================================

/// Processes that are high-value targets for attackers
const CRITICAL_PROCESSES: &[&str] = &[
    "system_server",
    "zygote",
    "zygote64",
    "surfaceflinger",
    "mediaserver",
    "installd",
    "vold",
    "netd",
];

/// Processes handling untrusted data (common attack surface)
const UNTRUSTED_DATA_PROCESSES: &[&str] = &[
    "com.android.chrome",
    "com.android.browser",
    "com.sec.android.gallery3d",
    "com.google.android.apps.photos",
    "com.whatsapp",
    "com.facebook.katana",
    "mediaserver",
    "media.codec",
];

/// Libraries known to have had vulnerabilities or commonly targeted
const SUSPICIOUS_LIBRARIES: &[&str] = &[
    "libstagefright",
    "libmediacodec",
    "libimagecodec",
    "libwebviewchromium",
    "libskia",
    "libpng",
    "libjpeg",
    "libheif",
    "libgui",
    "libbinder",
    "libcutils",
];

/// Function names that may indicate exploitation attempts
const VULNERABLE_FUNCTION_PATTERNS: &[&str] = &[
    "memcpy",
    "strcpy",
    "sprintf",
    "strcat",
    "malloc",
    "free",
    "realloc",
    "mmap",
    "processArea",      // Image processing
    "decode",           // Media decoding
    "parse",            // Parsing operations
    "deserialize",      // Deserialization
    "inflate",          // Decompression
];

/// Signals that indicate memory corruption (likely exploitation)
const MEMORY_CORRUPTION_SIGNALS: &[&str] = &[
    "SIGSEGV",   // Segmentation fault
    "SIGBUS",    // Bus error
    "SIGABRT",   // Abort (often heap corruption)
    "SIGILL",    // Illegal instruction
    "SIGTRAP",   // Trap (can indicate anti-debugging or exploitation)
];

/// Crash codes indicating specific memory issues
const EXPLOITATION_CODES: &[&str] = &[
    "SEGV_MAPERR",   // Address not mapped (NULL deref or bad pointer)
    "SEGV_ACCERR",   // Invalid permissions (heap/stack overflow)
    "BUS_ADRALN",    // Invalid address alignment
    "BUS_ADRERR",    // Non-existent physical address
    "ILL_ILLOPC",    // Illegal opcode (code corruption)
];

// ============================================================================
// DETECTOR IMPLEMENTATION
// ============================================================================

pub struct SuspiciousCrashDetector;

impl SuspiciousCrashDetector {
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // MEMORY PATTERN ANALYSIS
    // ========================================================================

    /// Comprehensive memory address analysis
    pub(crate) fn analyze_memory_pattern(&self, tombstone: &Tombstone) -> Option<MemoryAnalysis> {
        if tombstone.fault_addr.is_empty() {
            return None;
        }

        let addr = &tombstone.fault_addr;
        let mut indicators = Vec::new();
        
        let is_null_deref = self.is_null_dereference(addr);
        let is_heap_spray = self.detect_heap_spray_pattern(addr);
        let is_stack_pivot = self.detect_stack_pivot(tombstone);
        let is_rop_chain = self.analyze_rop_chain(&tombstone.backtrace);
        let is_kernel_space = self.is_kernel_space_address(addr);
        
        let address_type = self.classify_address(addr, tombstone);
        
        if is_null_deref {
            indicators.push("NULL pointer dereference detected".to_string());
        }
        
        if is_heap_spray {
            indicators.push("Heap spray pattern detected - repeating byte pattern".to_string());
        }
        
        if is_stack_pivot {
            indicators.push("Possible stack pivot - SP in unusual location".to_string());
        }
        
        if is_rop_chain {
            indicators.push("ROP chain likely - suspicious backtrace pattern".to_string());
        }
        
        if is_kernel_space {
            indicators.push("Kernel space address access from user mode".to_string());
        }

        // Check for common exploitation patterns
        if let Some(exploit_pattern) = self.detect_exploitation_pattern(addr) {
            indicators.push(exploit_pattern);
        }
        
        Some(MemoryAnalysis {
            is_null_deref,
            is_heap_spray,
            is_stack_pivot,
            is_rop_chain_likely: is_rop_chain,
            is_kernel_space,
            address_type,
            exploitation_indicators: indicators,
        })
    }

    /// Detect NULL pointer dereference (common crash, lower exploitation risk)
    pub(crate) fn is_null_dereference(&self, addr: &str) -> bool {
        if let Some(addr_hex) = addr.strip_prefix("0x") {
            if let Ok(value) = u64::from_str_radix(addr_hex, 16) {
                // NULL or very low address (first 64KB is NULL dereference range)
                return value < 0x10000;
            }
        }
        false
    }

    /// Detect heap spray patterns (repeating bytes indicate controlled memory)
    pub(crate) fn detect_heap_spray_pattern(&self, addr: &str) -> bool {
        if let Some(addr_hex) = addr.strip_prefix("0x") {
            if addr_hex.len() >= 8 {
                // Check for repeating 2-byte patterns
                let chunks: Vec<_> = addr_hex.chars()
                    .collect::<Vec<_>>()
                    .chunks(2)
                    .map(|c| c.iter().collect::<String>())
                    .collect();
                
                if chunks.len() >= 4 {
                    let first_pattern = &chunks[0];
                    let repeating_count = chunks.iter()
                        .filter(|&p| p == first_pattern)
                        .count();
                    
                    // If 50% or more chunks are the same pattern
                    if repeating_count >= chunks.len() / 2 {
                        return true;
                    }
                }
                
                // Check for common heap spray values
                let common_spray_patterns = [
                    "0c0c0c0c", "41414141", "42424242", "90909090",
                    "cccccccc", "deadbeef", "cafebabe", "baadf00d",
                ];
                
                for pattern in &common_spray_patterns {
                    if addr_hex.to_lowercase().contains(pattern) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Detect stack pivot (SP moved to unusual location)
    fn detect_stack_pivot(&self, tombstone: &Tombstone) -> bool {
        // Parse backtrace for stack pointer anomalies
        for frame in &tombstone.backtrace {
            let line = &frame.raw_line.to_lowercase();
            
            // Look for "sp" register in the raw line
            if line.contains("sp ") || line.contains("sp=") {
                // Extract SP value and check if it's in heap or code region
                // This is a simplified check - in reality you'd need the actual register values
                if let Some(sp_pos) = line.find("sp") {
                    let after_sp = &line[sp_pos..];
                    // If SP contains patterns like 0x7, it's likely stack
                    // If SP contains other patterns, might be pivoted
                    if !after_sp.contains("0x7") && !after_sp.contains("0xff") {
                        return true;
                    }
                }
            }
        }
        
        // Check if backtrace has very few frames (stack corruption)
        if tombstone.backtrace.len() <= 2 && !tombstone.backtrace.is_empty() {
            return true;
        }
        
        false
    }

    /// Detect ROP chain indicators in backtrace
    pub(crate) fn analyze_rop_chain(&self, backtrace: &[BacktraceFrame]) -> bool {
        if backtrace.len() < 3 {
            return false;
        }
        
        let mut suspicious_patterns = 0;
        
        for frame in backtrace {
            // ROP gadgets often point to small offsets in libraries
            if let Some(ref offset) = frame.offset {
                if let Ok(offset_val) = offset.parse::<u32>() {
                    // Very small offsets might indicate gadgets
                    if offset_val < 20 {
                        suspicious_patterns += 1;
                    }
                }
            }
            
            // Multiple frames in the same library at different offsets
            // (but not a normal call chain)
            if frame.function.is_none() && !frame.library.is_empty() {
                suspicious_patterns += 1;
            }
        }
        
        // If more than 30% of frames look suspicious
        suspicious_patterns > backtrace.len() / 3
    }

    /// Check if address is in kernel space
    pub(crate) fn is_kernel_space_address(&self, addr: &str) -> bool {
        if let Some(addr_hex) = addr.strip_prefix("0x") {
            if let Ok(value) = u64::from_str_radix(addr_hex, 16) {
                // Kernel space on ARM64 typically starts at 0xFFFF000000000000
                // On ARM32, it's 0xC0000000 and above
                return value >= 0xFFFF000000000000 || 
                       (value >= 0xC0000000 && value < 0x100000000);
            }
        }
        false
    }

    /// Classify the address type
    pub(crate) fn classify_address(&self, addr: &str, tombstone: &Tombstone) -> String {
        if self.is_null_dereference(addr) {
            return "null".to_string();
        }
        
        if self.is_kernel_space_address(addr) {
            return "kernel".to_string();
        }
        
        if let Some(addr_hex) = addr.strip_prefix("0x") {
            if let Ok(value) = u64::from_str_radix(addr_hex, 16) {
                // Rough heuristics for address classification
                // Stack addresses typically in 0x7f... range on ARM64
                if value >= 0x7f0000000000 && value < 0x800000000000 {
                    return "stack".to_string();
                }
                
                // Heap addresses typically in lower ranges
                if value >= 0x10000 && value < 0x7f0000000000 {
                    // Check if it's in a library (code) range
                    for frame in &tombstone.backtrace {
                        if !frame.pc.is_empty() {
                            if let Ok(pc_val) = u64::from_str_radix(&frame.pc, 16) {
                                // If fault address is near PC, likely code region
                                if value.abs_diff(pc_val) < 0x100000 {
                                    return "code".to_string();
                                }
                            }
                        }
                    }
                    return "heap".to_string();
                }
            }
        }
        
        "unknown".to_string()
    }

    /// Detect specific exploitation patterns
    fn detect_exploitation_pattern(&self, addr: &str) -> Option<String> {
        if let Some(addr_hex) = addr.strip_prefix("0x") {
            // Check for controlled addresses (shellcode patterns)
            let controlled_patterns = [
                ("41414141", "Controlled address (0x41414141) - likely buffer overflow"),
                ("42424242", "Controlled address (0x42424242) - likely buffer overflow"),
                ("43434343", "Controlled address (0x43434343) - likely buffer overflow"),
                ("deadbeef", "Controlled address (0xdeadbeef) - exploitation attempt"),
                ("cafebabe", "Controlled address (0xcafebabe) - exploitation attempt"),
            ];
            
            for (pattern, message) in &controlled_patterns {
                if addr_hex.to_lowercase().contains(pattern) {
                    return Some(message.to_string());
                }
            }
            
            // Check for aligned addresses (often used in exploits)
            if let Ok(value) = u64::from_str_radix(addr_hex, 16) {
                if value > 0x10000 && value % 0x1000 == 0 {
                    return Some("Page-aligned address - possibly controlled".to_string());
                }
            }
        }
        
        None
    }

    // ========================================================================
    // REGISTER ANALYSIS
    // ========================================================================

    /// Analyze register state from tombstone
    pub(crate) fn analyze_registers(&self, tombstone: &Tombstone) -> Option<RegisterAnalysis> {
        let registers = self.extract_registers(tombstone);
        
        if registers.is_empty() {
            return None;
        }
        
        let mut register_patterns = Vec::new();
        let mut pc_suspicious = false;
        let mut sp_suspicious = false;
        let mut lr_suspicious = false;
        let mut corruption_detected = false;
        
        // Analyze Program Counter (PC)
        if let Some(pc) = registers.get("pc") {
            if self.is_suspicious_pc(pc) {
                pc_suspicious = true;
                register_patterns.push(format!("Suspicious PC value: {}", pc));
            }
        }
        
        // Analyze Stack Pointer (SP)
        if let Some(sp) = registers.get("sp") {
            if self.is_suspicious_sp(sp) {
                sp_suspicious = true;
                register_patterns.push(format!("Suspicious SP value: {}", sp));
            }
        }
        
        // Analyze Link Register (LR) - return address
        if let Some(lr) = registers.get("lr") {
            if self.is_suspicious_lr(lr, &registers) {
                lr_suspicious = true;
                register_patterns.push(format!("Suspicious LR value: {}", lr));
            }
        }
        
        // Check for patterns in general-purpose registers
        let gp_patterns = self.analyze_general_purpose_registers(&registers);
        if !gp_patterns.is_empty() {
            register_patterns.extend(gp_patterns);
            corruption_detected = true;
        }
        
        // Check for register value patterns (heap spray, etc.)
        if self.detect_register_spray_pattern(&registers) {
            register_patterns.push("Register spray pattern detected".to_string());
            corruption_detected = true;
        }
        
        Some(RegisterAnalysis {
            pc_suspicious,
            sp_suspicious,
            lr_suspicious,
            register_patterns,
            corruption_detected,
            registers,
        })
    }

    /// Extract register values from tombstone
    fn extract_registers(&self, tombstone: &Tombstone) -> HashMap<String, String> {
        let mut registers = HashMap::new();
        
        // Parse from backtrace raw lines
        for frame in &tombstone.backtrace {
            let line = &frame.raw_line.trim();
            
            // Parse register lines like "x0  0000000000000002  x1  0000000000000000"
            if line.starts_with("x") || line.starts_with("lr ") || 
               line.starts_with("sp ") || line.starts_with("pc ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                
                let mut i = 0;
                while i < parts.len() {
                    if i + 1 < parts.len() {
                        let reg_name = parts[i];
                        let reg_value = parts[i + 1];
                        
                        // Validate it looks like a register
                        if (reg_name.starts_with('x') && reg_name.len() <= 3) ||
                           reg_name == "lr" || reg_name == "sp" || 
                           reg_name == "pc" || reg_name == "pst" {
                            registers.insert(reg_name.to_string(), reg_value.to_string());
                        }
                    }
                    i += 2;
                }
            }
        }
        
        registers
    }

    /// Check if PC (program counter) is suspicious
    fn is_suspicious_pc(&self, pc: &str) -> bool {
        if let Ok(value) = u64::from_str_radix(pc, 16) {
            // PC should be in code region
            // Suspicious if in stack, heap, or NULL regions
            if value < 0x10000 {
                return true;  // NULL or very low
            }
            
            if value >= 0x7f0000000000 {
                return true;  // Stack region
            }
            
            // Check for spray patterns
            if self.has_repeating_byte_pattern(pc) {
                return true;
            }
        }
        false
    }

    /// Check if SP (stack pointer) is suspicious
    fn is_suspicious_sp(&self, sp: &str) -> bool {
        if let Ok(value) = u64::from_str_radix(sp, 16) {
            // SP should be in stack region (high addresses)
            // Suspicious if in heap, code, or NULL regions
            if value < 0x7f0000000000 {
                return true;  // Too low for stack
            }
            
            // Check alignment (stack should be aligned)
            if value % 16 != 0 {
                return true;  // Misaligned stack
            }
        }
        false
    }

    /// Check if LR (link register) is suspicious
    fn is_suspicious_lr(&self, lr: &str, registers: &HashMap<String, String>) -> bool {
        if let Ok(value) = u64::from_str_radix(lr, 16) {
            // LR should point to code (return address)
            if value < 0x10000 {
                return true;  // NULL or very low
            }
            
            // Check if LR is wildly different from PC (might indicate corruption)
            if let Some(pc) = registers.get("pc") {
                if let Ok(pc_val) = u64::from_str_radix(pc, 16) {
                    // If LR and PC are very far apart, suspicious
                    if value.abs_diff(pc_val) > 0x10000000 {
                        return true;
                    }
                }
            }
            
            if self.has_repeating_byte_pattern(lr) {
                return true;
            }
        }
        false
    }

    /// Analyze general purpose registers for patterns
    fn analyze_general_purpose_registers(&self, registers: &HashMap<String, String>) -> Vec<String> {
        let mut patterns = Vec::new();
        
        // Check for controlled values (all same value)
        let mut value_counts: HashMap<String, usize> = HashMap::new();
        for (reg_name, reg_value) in registers {
            if reg_name.starts_with('x') {
                *value_counts.entry(reg_value.clone()).or_insert(0) += 1;
            }
        }
        
        for (value, count) in value_counts {
            if count >= 4 {
                patterns.push(format!("Multiple registers contain same value: {} ({} registers)", value, count));
            }
        }
        
        // Check for sequential values (might indicate controlled state)
        let mut sequential_count = 0;
        let mut prev_value: Option<u64> = None;
        
        for i in 0..29 {
            let reg_name = format!("x{}", i);
            if let Some(reg_value) = registers.get(&reg_name) {
                if let Ok(value) = u64::from_str_radix(reg_value, 16) {
                    if let Some(prev) = prev_value {
                        if value == prev + 1 || value == prev + 4 || value == prev + 8 {
                            sequential_count += 1;
                        }
                    }
                    prev_value = Some(value);
                }
            }
        }
        
        if sequential_count >= 3 {
            patterns.push(format!("Sequential register values detected ({} sequential)", sequential_count));
        }
        
        patterns
    }

    /// Detect spray patterns in registers
    pub(crate) fn detect_register_spray_pattern(&self, registers: &HashMap<String, String>) -> bool {
        let spray_patterns = ["41414141", "42424242", "0c0c0c0c", "90909090"];
        
        for reg_value in registers.values() {
            for pattern in &spray_patterns {
                if reg_value.to_lowercase().contains(pattern) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Check for repeating byte pattern in hex string
    fn has_repeating_byte_pattern(&self, hex: &str) -> bool {
        if hex.len() < 4 {
            return false;
        }
        
        let bytes: Vec<_> = hex.chars().collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .collect();
        
        if bytes.len() < 2 {
            return false;
        }
        
        let first_byte = &bytes[0];
        let repeat_count = bytes.iter().filter(|&b| b == first_byte).count();
        
        repeat_count >= bytes.len() / 2
    }

    /// Analyze crash information and detect suspicious patterns
    pub fn analyze(&self, crash_info: &CrashInfo) -> DetectionResult {
        let mut events = Vec::new();
        let mut anr_events = Vec::new();
        let mut process_count: HashMap<String, usize> = HashMap::new();
        let mut library_count: HashMap<String, usize> = HashMap::new();
        let mut pattern_count: HashMap<String, usize> = HashMap::new();

        // Analyze tombstones (crashes)
        for tombstone in &crash_info.tombstones {
            if let Some(event) = self.analyze_tombstone(tombstone) {
                // Track statistics
                *process_count.entry(event.process_name.clone()).or_insert(0) += 1;
                if let Some(ref lib) = event.suspicious_library {
                    *library_count.entry(lib.clone()).or_insert(0) += 1;
                }
                for indicator in &event.indicators {
                    *pattern_count.entry(indicator.clone()).or_insert(0) += 1;
                }
                
                events.push(event);
            }
        }

        // Analyze ANR traces
        if let Some(ref anr_trace) = crash_info.anr_trace {
            if let Some(event) = self.analyze_anr_trace(anr_trace) {
                anr_events.push(event);
            }
        }

        // Generate summary
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for event in &events {
            match event.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => {},
            }
        }

        for event in &anr_events {
            match event.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => {},
            }
        }

        // Get top processes and libraries
        let mut processes: Vec<_> = process_count.into_iter().collect();
        processes.sort_by(|a, b| b.1.cmp(&a.1));
        let most_targeted = processes.into_iter()
            .take(5)
            .map(|(k, v)| format!("{} ({} crashes)", k, v))
            .collect();

        let mut libraries: Vec<_> = library_count.into_iter().collect();
        libraries.sort_by(|a, b| b.1.cmp(&a.1));
        let most_exploited = libraries.into_iter()
            .take(5)
            .map(|(k, v)| format!("{} ({} crashes)", k, v))
            .collect();

        let mut patterns: Vec<_> = pattern_count.into_iter().collect();
        patterns.sort_by(|a, b| b.1.cmp(&a.1));
        let exploitation_patterns = patterns.into_iter()
            .take(5)
            .map(|(k, v)| format!("{} ({} occurrences)", k, v))
            .collect();

        DetectionResult {
            total_crashes: crash_info.tombstones.len(),
            suspicious_crashes: events.len(),
            total_anrs: if crash_info.anr_trace.is_some() { 1 } else { 0 },
            suspicious_anrs: anr_events.len(),
            events,
            anr_events,
            summary: DetectionSummary {
                critical_count: critical,
                high_count: high,
                medium_count: medium,
                low_count: low,
                most_targeted_processes: most_targeted,
                most_exploited_libraries: most_exploited,
                exploitation_patterns,
            },
        }
    }

    /// Analyze a single tombstone for suspicious indicators
    pub(crate) fn analyze_tombstone(&self, tombstone: &Tombstone) -> Option<SuspiciousCrashEvent> {
        let mut indicators = Vec::new();
        let mut severity = Severity::Low;
        let mut exploitation_likelihood = "Low";

        // Check 1: Memory corruption signal
        let is_memory_corruption = MEMORY_CORRUPTION_SIGNALS.contains(&tombstone.signal.as_str());
        if is_memory_corruption {
            indicators.push(format!("Memory corruption signal: {}", tombstone.signal));
            severity = Severity::Medium;
            exploitation_likelihood = "Medium";
        }

        // Check 2: Exploitation-prone crash code
        if EXPLOITATION_CODES.contains(&tombstone.code.as_str()) {
            indicators.push(format!("Exploitation-prone crash code: {}", tombstone.code));
            severity = Severity::High;
            exploitation_likelihood = "High";
        }

        // Check 3: Critical system process
        if CRITICAL_PROCESSES.iter().any(|&p| tombstone.process_name.contains(p)) {
            indicators.push(format!("Critical system process crashed: {}", tombstone.process_name));
            severity = Severity::Critical;
            exploitation_likelihood = "Very High";
        }

        // Check 4: Process handling untrusted data
        if UNTRUSTED_DATA_PROCESSES.iter().any(|&p| tombstone.process_name.contains(p)) {
            indicators.push(format!("Process handling untrusted data: {}", tombstone.process_name));
            if severity < Severity::Medium {
                severity = Severity::Medium;
            }
        }

        // Check 5: Privileged UID
        if tombstone.uid == 0 {
            indicators.push("Crash in root process (UID 0)".to_string());
            severity = Severity::Critical;
            exploitation_likelihood = "Very High";
        } else if tombstone.uid == 1000 {
            indicators.push("Crash in system process (UID 1000)".to_string());
            if severity < Severity::High {
                severity = Severity::High;
                exploitation_likelihood = "High";
            }
        }

        // Check 6: Suspicious library in backtrace
        let mut suspicious_lib = None;
        let mut vulnerable_func = None;
        
        for frame in &tombstone.backtrace {
            // Check library
            for &lib in SUSPICIOUS_LIBRARIES {
                if frame.library.contains(lib) {
                    indicators.push(format!("Crash in historically vulnerable library: {}", lib));
                    suspicious_lib = Some(lib.to_string());
                    if severity < Severity::High {
                        severity = Severity::High;
                        exploitation_likelihood = "High";
                    }
                    break;
                }
            }

            // Check function name
            if let Some(ref func) = frame.function {
                for &pattern in VULNERABLE_FUNCTION_PATTERNS {
                    if func.to_lowercase().contains(&pattern.to_lowercase()) {
                        indicators.push(format!("Crash in potentially vulnerable function: {}", pattern));
                        vulnerable_func = Some(func.clone());
                        if severity < Severity::Medium {
                            severity = Severity::Medium;
                        }
                        break;
                    }
                }
            }
        }

        // Check 7: Abort message indicating heap corruption
        if !tombstone.abort_message.is_empty() {
            if tombstone.abort_message.contains("heap") ||
               tombstone.abort_message.contains("corrupt") ||
               tombstone.abort_message.contains("free") ||
               tombstone.abort_message.contains("double") {
                indicators.push(format!("Heap corruption detected: {}", tombstone.abort_message));
                severity = Severity::Critical;
                exploitation_likelihood = "Very High";
            }
        }

        // Check 8: Suspicious fault address patterns
        if !tombstone.fault_addr.is_empty() {
            // NULL pointer dereference
            if tombstone.fault_addr.ends_with("0000") || tombstone.fault_addr == "0x0" {
                indicators.push("NULL pointer dereference".to_string());
            }
            // Very low or very high addresses (often exploitation)
            else if self.is_suspicious_address(&tombstone.fault_addr) {
                indicators.push(format!("Suspicious memory address: {}", tombstone.fault_addr));
                if severity < Severity::High {
                    severity = Severity::High;
                    exploitation_likelihood = "High";
                }
            }
        }

        // Check 9: Short backtrace (might indicate stack corruption)
        if tombstone.backtrace.len() <= 2 && !tombstone.backtrace.is_empty() {
            indicators.push(format!("Short backtrace ({} frames) - possible stack corruption", tombstone.backtrace.len()));
        }

        // Perform advanced memory analysis
        let memory_analysis = self.analyze_memory_pattern(tombstone);
        if let Some(ref mem_analysis) = memory_analysis {
            for indicator in &mem_analysis.exploitation_indicators {
                indicators.push(indicator.clone());
                
                // Upgrade severity based on memory analysis
                if mem_analysis.is_heap_spray || mem_analysis.is_rop_chain_likely {
                    if severity < Severity::Critical {
                        severity = Severity::Critical;
                        exploitation_likelihood = "Very High";
                    }
                }
            }
        }

        // Perform register analysis
        let register_analysis = self.analyze_registers(tombstone);
        if let Some(ref reg_analysis) = register_analysis {
            for pattern in &reg_analysis.register_patterns {
                indicators.push(pattern.clone());
                
                // Upgrade severity if register corruption detected
                if reg_analysis.corruption_detected && severity < Severity::High {
                    severity = Severity::High;
                    if exploitation_likelihood == "Low" || exploitation_likelihood == "Medium" {
                        exploitation_likelihood = "High";
                    }
                }
            }
        }

        // Only create event if there are suspicious indicators
        if !indicators.is_empty() {
            Some(SuspiciousCrashEvent {
                event_type: "suspicious_crash".to_string(),
                severity,
                pid: tombstone.pid,
                tid: tombstone.tid,
                uid: tombstone.uid,
                process_name: tombstone.process_name.clone(),
                thread_name: tombstone.thread_name.clone(),
                signal: tombstone.signal.clone(),
                crash_reason: format!("{} ({})", tombstone.signal, tombstone.code),
                indicators,
                exploitation_likelihood: exploitation_likelihood.to_string(),
                timestamp: tombstone.timestamp.clone(),
                fault_address: if tombstone.fault_addr.is_empty() { 
                    None 
                } else { 
                    Some(tombstone.fault_addr.clone()) 
                },
                abort_message: if tombstone.abort_message.is_empty() { 
                    None 
                } else { 
                    Some(tombstone.abort_message.clone()) 
                },
                suspicious_library: suspicious_lib,
                vulnerable_function: vulnerable_func,
                mitigation_recommendations: self.generate_mitigations(&tombstone, &severity),
                memory_analysis,
                register_analysis,
            })
        } else {
            None
        }
    }

    // ========================================================================
    // ANR (APPLICATION NOT RESPONDING) ANALYSIS
    // ========================================================================

    /// Analyze ANR trace for suspicious patterns
    pub(crate) fn analyze_anr_trace(&self, anr_trace: &AnrTrace) -> Option<AnrEvent> {
        let mut indicators = Vec::new();
        let mut severity = Severity::Low;
        let mut exploitation_likelihood = "Low";
        let mut anr_type = "unknown".to_string();
        
        // Extract process info
        let pid: u32 = anr_trace.process_info.get("pid")
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        
        let process_name = anr_trace.process_info.get("cmd_line")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        
        // Count blocked threads
        let blocked_threads = anr_trace.threads.iter()
            .filter(|t| self.is_thread_blocked(t))
            .count();
        
        let main_thread_blocked = anr_trace.threads.iter()
            .any(|t| t.name == "main" && self.is_thread_blocked(t));
        
        // Check 1: Deadlock detection
        if let Some(deadlock_info) = self.detect_deadlock(&anr_trace.threads) {
            indicators.push("Potential deadlock detected".to_string());
            indicators.push(deadlock_info.clone());
            anr_type = "deadlock".to_string();
            severity = Severity::High;
            exploitation_likelihood = "Medium";
        }
        
        // Check 2: Binder deadlock (common in exploitation)
        if self.detect_binder_deadlock(&anr_trace.threads) {
            indicators.push("Binder IPC deadlock detected - possible exploitation".to_string());
            anr_type = "deadlock".to_string();
            severity = Severity::High;
            exploitation_likelihood = "High";
        }
        
        // Check 3: Critical system process ANR
        if CRITICAL_PROCESSES.iter().any(|&p| process_name.contains(p)) {
            indicators.push(format!("Critical system process ANR: {}", process_name));
            severity = Severity::Critical;
            exploitation_likelihood = "High";
        }
        
        // Check 4: Suspicious native code execution
        if let Some(native_info) = self.detect_suspicious_native_code(&anr_trace.threads) {
            indicators.push("Suspicious native code in ANR trace".to_string());
            indicators.push(native_info.clone());
            anr_type = "suspicious_native".to_string();
            if severity < Severity::High {
                severity = Severity::High;
                exploitation_likelihood = "Medium";
            }
        }
        
        // Check 5: Infinite loop detection
        if self.detect_infinite_loop(&anr_trace.threads) {
            indicators.push("Possible infinite loop detected".to_string());
            anr_type = "infinite_loop".to_string();
            if severity < Severity::Medium {
                severity = Severity::Medium;
            }
        }
        
        // Check 6: Many threads blocked (resource exhaustion)
        if blocked_threads > 10 {
            indicators.push(format!("High number of blocked threads: {}", blocked_threads));
            anr_type = "resource_exhaustion".to_string();
            if severity < Severity::Medium {
                severity = Severity::Medium;
                exploitation_likelihood = "Low";
            }
        }
        
        // Check 7: Main thread blocked on suspicious operation
        if main_thread_blocked {
            if let Some(main_thread) = anr_trace.threads.iter().find(|t| t.name == "main") {
                if self.is_suspicious_blocking_operation(main_thread) {
                    indicators.push("Main thread blocked on suspicious operation".to_string());
                    if severity < Severity::High {
                        severity = Severity::High;
                    }
                }
            }
        }
        
        // Only create event if there are indicators
        if !indicators.is_empty() {
            Some(AnrEvent {
                event_type: "suspicious_anr".to_string(),
                severity,
                pid,
                process_name,
                anr_type: anr_type.clone(),
                blocked_threads,
                main_thread_blocked,
                indicators,
                exploitation_likelihood: exploitation_likelihood.to_string(),
                deadlock_details: self.get_deadlock_details(&anr_trace.threads),
                suspicious_native_code: self.get_native_code_details(&anr_trace.threads),
                mitigation_recommendations: self.generate_anr_mitigations(&anr_type, &severity),
            })
        } else {
            None
        }
    }

    /// Check if a thread is blocked
    fn is_thread_blocked(&self, thread: &Thread) -> bool {
        matches!(thread.status.as_str(), "Blocked" | "Waiting" | "Sleeping" | "TimedWaiting")
    }

    /// Detect deadlock patterns in threads
    fn detect_deadlock(&self, threads: &[Thread]) -> Option<String> {
        // Look for circular wait patterns
        let mut waiting_on: HashMap<u32, Vec<u32>> = HashMap::new();
        
        for thread in threads {
            if self.is_thread_blocked(thread) {
                // Check if thread is waiting on a lock
                for (key, value) in &thread.properties {
                    if key.contains("waiting") || key.contains("lock") {
                        // Try to extract TID of lock holder
                        if let Some(holder_tid) = self.extract_tid_from_property(value) {
                            waiting_on.entry(thread.tid).or_insert_with(Vec::new).push(holder_tid);
                        }
                    }
                }
            }
        }
        
        // Check for circular dependencies
        for (tid, waiting) in &waiting_on {
            if self.has_circular_dependency(*tid, waiting, &waiting_on, &mut Vec::new()) {
                return Some(format!("Circular wait detected involving TID {}", tid));
            }
        }
        
        None
    }

    /// Check for circular dependency in wait graph
    fn has_circular_dependency(
        &self,
        start_tid: u32,
        current_waiting: &[u32],
        wait_graph: &HashMap<u32, Vec<u32>>,
        visited: &mut Vec<u32>,
    ) -> bool {
        for &tid in current_waiting {
            if tid == start_tid {
                return true;
            }
            
            if visited.contains(&tid) {
                continue;
            }
            
            visited.push(tid);
            
            if let Some(next_waiting) = wait_graph.get(&tid) {
                if self.has_circular_dependency(start_tid, next_waiting, wait_graph, visited) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Extract TID from property value
    fn extract_tid_from_property(&self, value: &str) -> Option<u32> {
        // Look for patterns like "tid=123" or just numbers
        if let Some(tid_pos) = value.find("tid=") {
            let after_tid = &value[tid_pos + 4..];
            if let Some(end) = after_tid.find(|c: char| !c.is_numeric()) {
                after_tid[..end].parse().ok()
            } else {
                after_tid.parse().ok()
            }
        } else {
            // Try to parse as number
            value.parse().ok()
        }
    }

    /// Detect Binder-specific deadlocks
    fn detect_binder_deadlock(&self, threads: &[Thread]) -> bool {
        let binder_threads: Vec<_> = threads.iter()
            .filter(|t| t.name.contains("Binder") || 
                       t.stack_trace.iter().any(|f| f.library.contains("libbinder")))
            .collect();
        
        if binder_threads.len() < 2 {
            return false;
        }
        
        // Check if multiple binder threads are blocked
        let blocked_binder = binder_threads.iter()
            .filter(|t| self.is_thread_blocked(t))
            .count();
        
        blocked_binder >= 2
    }

    /// Detect suspicious native code in ANR
    fn detect_suspicious_native_code(&self, threads: &[Thread]) -> Option<String> {
        for thread in threads {
            for frame in &thread.stack_trace {
                if frame.frame_type == "native" {
                    // Check for suspicious libraries
                    for &lib in SUSPICIOUS_LIBRARIES {
                        if frame.library.contains(lib) {
                            return Some(format!("Native code in {}: {}", lib, frame.details));
                        }
                    }
                    
                    // Check for long-running native operations
                    if frame.details.contains("decode") || 
                       frame.details.contains("parse") ||
                       frame.details.contains("inflate") {
                        return Some(format!("Long-running native operation: {}", frame.details));
                    }
                }
            }
        }
        
        None
    }

    /// Detect infinite loop patterns
    fn detect_infinite_loop(&self, threads: &[Thread]) -> bool {
        for thread in threads {
            if thread.status == "Runnable" && !self.is_thread_blocked(thread) {
                // Check if stack trace shows repeated calls
                if thread.stack_trace.len() > 5 {
                    let methods: Vec<_> = thread.stack_trace.iter()
                        .map(|f| f.method.as_str())
                        .collect();
                    
                    // Look for same method appearing multiple times consecutively
                    for i in 0..methods.len().saturating_sub(3) {
                        if methods[i] == methods[i+1] && methods[i] == methods[i+2] {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }

    /// Check if thread is blocked on suspicious operation
    fn is_suspicious_blocking_operation(&self, thread: &Thread) -> bool {
        for frame in &thread.stack_trace {
            // Suspicious if waiting on network I/O, file I/O from untrusted source
            if frame.method.contains("read") || frame.method.contains("write") {
                if frame.method.contains("Socket") || frame.method.contains("File") {
                    return true;
                }
            }
            
            // Suspicious if waiting on JNI call
            if frame.method.contains("JNI") || frame.frame_type == "native" {
                return true;
            }
        }
        
        false
    }

    /// Get deadlock details for reporting
    fn get_deadlock_details(&self, threads: &[Thread]) -> Option<String> {
        let blocked: Vec<_> = threads.iter()
            .filter(|t| self.is_thread_blocked(t))
            .map(|t| format!("{} (TID: {})", t.name, t.tid))
            .collect();
        
        if blocked.len() >= 2 {
            Some(format!("Blocked threads: {}", blocked.join(", ")))
        } else {
            None
        }
    }

    /// Get native code details for reporting
    fn get_native_code_details(&self, threads: &[Thread]) -> Option<String> {
        for thread in threads {
            for frame in &thread.stack_trace {
                if frame.frame_type == "native" {
                    for &lib in SUSPICIOUS_LIBRARIES {
                        if frame.library.contains(lib) {
                            return Some(format!("{} in {}", frame.details, frame.library));
                        }
                    }
                }
            }
        }
        None
    }

    /// Generate mitigation recommendations for ANR
    fn generate_anr_mitigations(&self, anr_type: &str, severity: &Severity) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        match severity {
            Severity::Critical | Severity::High => {
                recommendations.push("Immediate investigation required - ANR may indicate active exploitation or DoS attack".to_string());
            }
            _ => {}
        }
        
        match anr_type {
            "deadlock" => {
                recommendations.push("Analyze thread dump for circular dependencies".to_string());
                recommendations.push("Review synchronization logic in affected components".to_string());
                recommendations.push("Check for Binder transaction timeouts".to_string());
            }
            "resource_exhaustion" => {
                recommendations.push("Monitor system resources and thread count".to_string());
                recommendations.push("Check for resource leaks or DoS attack".to_string());
            }
            "suspicious_native" => {
                recommendations.push("Review native code in affected library".to_string());
                recommendations.push("Check for malformed input causing hang".to_string());
                recommendations.push("Update library if patch available".to_string());
            }
            "infinite_loop" => {
                recommendations.push("Analyze code path for loop exit conditions".to_string());
                recommendations.push("Check for malicious input causing infinite processing".to_string());
            }
            _ => {
                recommendations.push("Review ANR trace for unusual patterns".to_string());
                recommendations.push("Monitor for repeated ANRs".to_string());
            }
        }
        
        recommendations
    }

    /// Check if a memory address is suspicious
    pub(crate) fn is_suspicious_address(&self, addr: &str) -> bool {
        // Use the comprehensive memory analysis
        self.is_null_dereference(addr) ||
        self.is_kernel_space_address(addr) ||
        self.detect_heap_spray_pattern(addr)
    }

    /// Generate mitigation recommendations based on crash characteristics
    fn generate_mitigations(&self, tombstone: &Tombstone, severity: &Severity) -> Vec<String> {
        let mut recommendations = Vec::new();

        match severity {
            Severity::Critical | Severity::High => {
                recommendations.push("Immediate investigation required - potential active exploitation".to_string());
                recommendations.push("Isolate affected device and preserve forensic evidence".to_string());
                recommendations.push("Check for indicators of compromise (IOCs) on device".to_string());
            }
            _ => {}
        }

        if CRITICAL_PROCESSES.iter().any(|&p| tombstone.process_name.contains(p)) {
            recommendations.push("Critical system process affected - perform full security audit".to_string());
            recommendations.push("Check system logs for unusual activity before crash".to_string());
        }

        if tombstone.uid == 0 || tombstone.uid == 1000 {
            recommendations.push("Privileged process crashed - review all recent system changes".to_string());
            recommendations.push("Verify system partition integrity".to_string());
        }

        if !tombstone.abort_message.is_empty() && 
           (tombstone.abort_message.contains("heap") || tombstone.abort_message.contains("corrupt")) {
            recommendations.push("Heap corruption detected - likely memory safety vulnerability".to_string());
            recommendations.push("Update affected library/component if patch available".to_string());
        }

        if UNTRUSTED_DATA_PROCESSES.iter().any(|&p| tombstone.process_name.contains(p)) {
            recommendations.push("Review recently accessed files/URLs before crash".to_string());
            recommendations.push("Consider sandboxing or restricting app permissions".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("Monitor for repeated crashes with similar patterns".to_string());
            recommendations.push("Keep system and apps updated to latest security patches".to_string());
        }

        recommendations
    }
}

impl Default for SuspiciousCrashDetector {
    fn default() -> Self {
        Self::new()
    }
}