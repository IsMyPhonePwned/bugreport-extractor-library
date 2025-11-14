use super::Parser;
use serde_json::{json, Value};
use std::error::Error;
use std::collections::HashMap;
use serde::Serialize;

/// Represents a single thread. Fields are optional as they may come from 'top' or 'ps'.
#[derive(Serialize, Debug, Clone)]
struct ThreadInfo {
    tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_percent: Option<f64>,
    status: String,
    name: String,
}

/// Represents a process, containing multiple threads.
#[derive(Serialize, Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    virt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    res: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcy: Option<String>,
    cmd: String,
    threads: HashMap<u32, ThreadInfo>,
}

impl ProcessInfo {
    /// Helper to create a new, minimal process entry from 'ps' data
    fn from_ps_line(pid: u32, user: &str, name: &str) -> Self {
        ProcessInfo {
            pid,
            user: user.to_string(),
            virt: None,
            res: None,
            pcy: None,
            cmd: name.to_string(),
            threads: HashMap::new(),
        }
    }
}

/// A parser for 'CPU INFO (top -H ...)' and 'PROCESSES AND THREADS (ps -A -T...)' sections.
pub struct ProcessParser;

impl Default for ProcessParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Process Parser")
    }
}

impl ProcessParser {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(ProcessParser)
    }

    /// Extracts the column map from the `top` command's "-o" argument.
    fn create_top_header_map(command_line: &str) -> Option<HashMap<String, usize>> {
        let parts: Vec<&str> = command_line.split_whitespace().collect();
        if let Some(o_index) = parts.iter().position(|&s| s == "-o") {
            if o_index + 1 < parts.len() {
                let columns = parts[o_index + 1];
                let map: HashMap<String, usize> = columns.split(',')
                    .enumerate()
                    .map(|(i, name)| (name.to_lowercase(), i)) // Use lowercase for consistency
                    .collect();
                return Some(map);
            }
        }
        None
    }
    
    /// Finds the header line and creates a map of column names to their index for 'ps'
    fn create_ps_header_map(header_line: &str) -> HashMap<String, usize> {
        header_line.split_whitespace()
            .enumerate()
            .map(|(i, name)| (name.to_lowercase(), i))
            .collect()
    }

    /// Parses the 'CPU INFO (top -H ...)' section
    fn parse_top_section(content: &str, processes: &mut HashMap<u32, ProcessInfo>) {
        const START_DELIMITER: &str = "------ CPU INFO (top ";
        
        if let Some(start_index) = content.find(START_DELIMITER) {
            let block_start = start_index + START_DELIMITER.len();
            
            if let Some(command_line_end) = content[block_start..].find(") ------\n") {
                let command_line = &content[block_start .. block_start + command_line_end];
                let data_block_start = block_start + command_line_end + ") ------\n".len();
                
                if let Some(data_block) = content[data_block_start..].split("------ ").next() {
                    if let Some(col_map) = Self::create_top_header_map(command_line) {
                        
                        let (pid_idx, tid_idx, user_idx, cpu_idx, s_idx, virt_idx, res_idx, pcy_idx, cmd_idx, name_idx) = (
                            col_map.get("pid"), col_map.get("tid"), col_map.get("user"),
                            col_map.get("%cpu"), col_map.get("s"), col_map.get("virt"),
                            col_map.get("res"), col_map.get("pcy"), col_map.get("cmd"),
                            col_map.get("name")
                        );
                        
                        if let (Some(&pid_idx), Some(&tid_idx), Some(&user_idx), Some(&cpu_idx), Some(&s_idx), Some(&name_idx), Some(&cmd_idx)) = 
                            (pid_idx, tid_idx, user_idx, cpu_idx, s_idx, name_idx, cmd_idx) {
                            
                            let mut lines = data_block.lines();
                            lines.find(|l| l.trim().starts_with("PID")); // Skip headers

                            for line in lines {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() < col_map.len() { continue; }

                                if let (Ok(pid), Ok(tid), Ok(cpu_percent)) = (
                                    parts[pid_idx].parse::<u32>(),
                                    parts[tid_idx].parse::<u32>(),
                                    parts[cpu_idx].parse::<f64>(),
                                ) {
                                    let thread = ThreadInfo {
                                        tid,
                                        cpu_percent: Some(cpu_percent),
                                        status: parts[s_idx].to_string(),
                                        name: parts[cmd_idx].to_string(), // Thread name is CMD
                                    };
                                    
                                    let process_entry = processes.entry(pid).or_insert_with(|| {
                                        ProcessInfo {
                                            pid,
                                            user: parts[user_idx].to_string(),
                                            virt: virt_idx.map(|&i| parts.get(i).map_or("".to_string(), |s| (*s).to_string())),
                                            res: res_idx.map(|&i| parts.get(i).map_or("".to_string(), |s| (*s).to_string())),
                                            pcy: pcy_idx.map(|&i| parts.get(i).map_or("".to_string(), |s| (*s).to_string())),
                                            cmd: parts[name_idx].to_string(), // Process name is NAME
                                            threads: HashMap::new(),
                                        }
                                    });
                                    process_entry.threads.insert(tid, thread);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Parses the 'PROCESSES AND THREADS (ps -A -T...)' section
    fn parse_ps_section(content: &str, processes: &mut HashMap<u32, ProcessInfo>) {
        const START_DELIMITER: &str = "------ PROCESSES AND THREADS (ps -A -T";
        
        if let Some(start_index) = content.find(START_DELIMITER) {
            let block_start = start_index + START_DELIMITER.len();
            
            if let Some(data_block) = content[block_start..].split("------ ").next() {
                let mut lines = data_block.lines();
                
                let header_line = lines.find(|l| l.trim().to_lowercase().starts_with("label"));
                
                if let Some(header) = header_line {
                    // Use 'comm' (command) as the name
                    let col_map = Self::create_ps_header_map(&header.to_lowercase());

                    let (pid_idx, tid_idx, user_idx, s_idx, name_idx) = (
                        col_map.get("pid"), col_map.get("tid"), col_map.get("user"),
                        col_map.get("stat"), col_map.get("comm")
                    );
                    
                    if let (Some(&pid_idx), Some(&tid_idx), Some(&user_idx), Some(&s_idx), Some(&name_idx)) = 
                        (pid_idx, tid_idx, user_idx, s_idx, name_idx) {

                        for line in lines {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() <= *col_map.values().max().unwrap_or(&0) {
                                continue; // Not a valid data line
                            }

                            if let (Ok(pid), Ok(tid)) = (
                                parts[pid_idx].parse::<u32>(),
                                parts[tid_idx].parse::<u32>(),
                            ) {
                                let user = parts[user_idx];
                                let status = parts[s_idx].to_string();
                                let name = parts[name_idx].to_string();

                                let process_entry = processes.entry(pid).or_insert_with(|| {
                                    // This process wasn't in 'top', create it.
                                    ProcessInfo::from_ps_line(pid, user, &name)
                                });
                                
                                // If this is the main thread (PID == TID), update the process's command.
                                if pid == tid {
                                    process_entry.cmd = name.clone();
                                }

                                // Get or create the thread
                                let thread_entry = process_entry.threads.entry(tid).or_insert_with(|| {
                                    // This thread wasn't in 'top', create it
                                    ThreadInfo {
                                        tid,
                                        cpu_percent: None, // 'ps' doesn't provide %CPU
                                        status: status.clone(),
                                        name: name.clone(),
                                    }
                                });
                                
                                // Update status and name from 'ps' as it's the source of truth
                                thread_entry.status = status;
                                thread_entry.name = name;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Parser for ProcessParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut processes: HashMap<u32, ProcessInfo> = HashMap::new();

        // Run the 'top' parser first to get rich info
        Self::parse_top_section(&content, &mut processes);
        
        // Run the 'ps' parser to add/enrich with more threads/processes
        Self::parse_ps_section(&content, &mut processes);

        // Convert the final HashMap into a flat Vec for JSON output
        let final_list: Vec<Value> = processes.values().map(|p| {
            let mut p_json = serde_json::to_value(p).unwrap();
            // Convert threads map to a vec
            p_json["threads"] = json!(p.threads.values().collect::<Vec<_>>());
            p_json
        }).collect();
        
        Ok(json!(final_list))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    #[test]
    fn test_parse_cpu_info_block() {
        let data = b"
Junk before
------ CPU INFO (top -b -n 1 -H -s 6 -o pid,tid,user,pr,ni,%cpu,s,virt,res,pcy,cmd,name) ------
Threads: 5755 total,   4 running, 5751 sleeping,   0 stopped,   0 zombie
  PID   TID USER         PR  NI[%CPU]S VIRT  RES PCY CMD             NAME
 1486  4292 system        0 -20 93.9 R  24G 369M  fg binder:1486_11  system_server
 1486  5561 system        0 -20 71.0 R  24G 369M  fg binder:1486_1F  system_server
22559 22559 shell         0 -20 49.3 R  10G 8.7M  fg top             top
------ PROCESSES AND THREADS (ps -A -T -Z -O u,pid,tid,ppid,vsz,rss,wchan,stat,rtprio,sched,comm,time,nl) ------
LABEL                          USER           PID   TID   PPID      VSZ    RSS WCHAN            STAT RTPRIO SCHED COMM             TIME NL
u:r:system_server:s0           system          1486  1486   878   25324084 378416 0                   S    19   0 system_server    00:11:33  1
u:r:system_server:s0           system          1486  4292   878   25324084 378416 0                   R    19   0 binder:1486_11   00:00:17  1
u:r:shell:s0                   shell          22559 22559 22558    10516 8920 0                   R    19   0 top              00:00:00  1
u:r:untrusted_app:s0:c1,c2,c3  notsystem      30000 30000   878    10000  1000 0                   S    19   0 com.new.app      00:00:01  1
u:r:untrusted_app:s0:c1,c2,c3  notsystem      30000 30001   878    10000  1000 0                   S    19   0 pool-3-thread-1  00:00:00  1
        ";
        
        let parser = ProcessParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        let result_vec: Vec<Value> = serde_json::from_value(result).unwrap();

        // Find process 1486 (from 'top' and 'ps')
        let p1486 = result_vec.iter().find(|p| p["pid"] == 1486).unwrap();
        assert_eq!(p1486["user"], "system");
        assert_eq!(p1486["virt"], "24G"); // From top
        assert_eq!(p1486["cmd"], "system_server"); // Correctly set from 'ps'
        let p1486_threads: Vec<Value> = serde_json::from_value(p1486["threads"].clone()).unwrap();
        assert_eq!(p1486_threads.len(), 3); // 1486, 4292, 5561
        
        // Check thread 4292 (from 'top' and 'ps')
        let t4292 = p1486_threads.iter().find(|t| t["tid"] == 4292).unwrap();
        assert_eq!(t4292["cpu_percent"], 93.9); // From top
        assert_eq!(t4292["status"], "R"); // From ps
        assert_eq!(t4292["name"], "binder:1486_11"); // From ps

        // Check thread 5561 (from 'top' only)
        let t5561 = p1486_threads.iter().find(|t| t["tid"] == 5561).unwrap();
        assert_eq!(t5561["cpu_percent"], 71.0); // From top
        assert_eq!(t5561["status"], "R"); // From top
        assert_eq!(t5561["name"], "binder:1486_1F"); // From top's CMD

        // Check thread 1486 (from 'ps' only - the main process thread)
        let t1486 = p1486_threads.iter().find(|t| t["tid"] == 1486).unwrap();
        assert_eq!(t1486["cpu_percent"], Value::Null); // Not in top
        assert_eq!(t1486["status"], "S"); // From ps
        assert_eq!(t1486["name"], "system_server"); // From ps

        // Find process 22559 (from 'top' and 'ps')
        let p22559 = result_vec.iter().find(|p| p["pid"] == 22559).unwrap();
        assert_eq!(p22559["user"], "shell");
        assert_eq!(p22559["cmd"], "top");
        let p22559_threads: Vec<Value> = serde_json::from_value(p22559["threads"].clone()).unwrap();
        assert_eq!(p22559_threads.len(), 1);
        assert_eq!(p22559_threads[0]["tid"], 22559);
        assert_eq!(p22559_threads[0]["cpu_percent"], 49.3);
        assert_eq!(p22559_threads[0]["name"], "top");

        // Find process 30000 (from 'ps' only)
        let p30000 = result_vec.iter().find(|p| p["pid"] == 30000).unwrap();
        assert_eq!(p30000["user"], "notsystem");
        assert_eq!(p30000["cmd"], "com.new.app"); // Set from main process line
        assert_eq!(p30000["virt"], Value::Null); // Not in top
        let p30000_threads: Vec<Value> = serde_json::from_value(p30000["threads"].clone()).unwrap();
        assert_eq!(p30000_threads.len(), 2); // 30000, 30001
        
        let t30001 = p30000_threads.iter().find(|t| t["tid"] == 30001).unwrap();
        assert_eq!(t30001["name"], "pool-3-thread-1");
    }
}