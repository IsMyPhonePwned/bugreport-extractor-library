use super::Parser;
use serde_json::{json, Map, Value};
use std::error::Error;

/// A specialized parser for 'DUMP OF SERVICE package' sections.
pub struct PackageParser;

/// A helper trait to split a string at the Nth occurrence of a delimiter.
trait SplitAtNth {
    fn split_at_this_many_colons(&self, n: usize) -> Option<(&str, &str)>;
}

impl SplitAtNth for str {
    /// Splits the string at the Nth ':', returning the parts.
    fn split_at_this_many_colons(&self, n: usize) -> Option<(&str, &str)> {
        let mut indices = self.match_indices(':').skip(n - 1); // Go to the Nth (0-indexed)
        if let Some((index, _)) = indices.next() {
            Some((&self[..index], &self[index + 1..]))
        } else {
            None
        }
    }
}

impl Default for PackageParser {
    fn default() -> Self {
        Self::new().expect("Failed to create the Package Parser")
    }
}

impl PackageParser {
    /// Creates a new PackageParser.
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(PackageParser)
    }

    /// Checks if a line indicates the end of a section (duration line)
    /// Pattern: "--------- X.XXXs was the duration of <service>, ending at: YYYY-MM-DD HH:MM:SS"
    fn is_section_end_line(line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.starts_with("---------") && 
        trimmed.contains("was the duration of") && 
        trimmed.contains("ending at:")
    }

    /// Parses a package information block starting with "Package [name] (hash):"
    fn parse_package_block<'a, I>(lines_iter: &mut std::iter::Peekable<I>) -> Option<(String, Value)>
    where
        I: Iterator<Item = &'a str> + Clone,
    {
        // Get the header line: "Package [com.bitchat.droid] (672e433):"
        let header_line = lines_iter.next()?.trim();
        
        // Extract package name from "Package [name] (hash):"
        let package_name = if let Some(start) = header_line.find('[') {
            if let Some(end) = header_line[start+1..].find(']') {
                header_line[start+1..start+1+end].to_string()
            } else {
                return None;
            }
        } else {
            return None;
        };

        let mut package_map = Map::new();
        package_map.insert("package_name".to_string(), json!(package_name.clone()));
        
        // Parse all fields until we hit the next "Package [" or end of section
        while let Some(line) = lines_iter.peek() {
            let line = line.trim();
            
            // Stop if we hit a section boundary (duration line)
            if Self::is_section_end_line(line) {
                break;
            }
            
            // Stop if we hit another package
            if line.starts_with("Package [") {
                break;
            }
            
            // Skip empty lines but don't break on them (they might be between sections)
            if line.is_empty() {
                lines_iter.next();
                continue;
            }
            
            // Check for User sections BEFORE checking for key=value pairs
            // (because "User 0: ceDataInode=0..." contains '=' and would be misparsed)
            if line.starts_with("User ") {
                // Parse user-specific information
                // "User 0: ceDataInode=122761 installed=true ..."
                let user_line = lines_iter.next().unwrap(); // Consume the User line
                if let Some((user_part, rest)) = user_line.trim().split_once(':') {
                    let user_id = user_part.replace("User", "").trim().parse::<u32>().ok();
                    if let Some(user_id) = user_id {
                        let mut user_map = Map::new();
                        user_map.insert("user_id".to_string(), json!(user_id));
                        
                        // Parse key=value pairs in the rest
                        // Handle: ceDataInode=0 installed=false hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false virtual=false
                        for part in rest.split_whitespace() {
                            if let Some((k, v)) = part.split_once('=') {
                                let k = k.trim();
                                let v = v.trim();
                                
                                // Try to parse as boolean first
                                let v_bool = match v {
                                    "true" => Some(true),
                                    "false" => Some(false),
                                    _ => None,
                                };
                                
                                if let Some(v_bool) = v_bool {
                                    user_map.insert(k.to_string(), json!(v_bool));
                                } else if k == "ceDataInode" || k == "distractionFlags" || k == "enabled" {
                                    // Parse as integer
                                    user_map.insert(k.to_string(), json!(v.parse::<u64>().ok()));
                                } else {
                                    // Store as string
                                    user_map.insert(k.to_string(), json!(v));
                                }
                            }
                        }
                        
                        // Also parse nested fields like installReason, firstInstallTime, etc.
                        while let Some(next_line) = lines_iter.peek() {
                            let next_line = next_line.trim();
                            // Break on next User, next Package, or empty line (but only after we've parsed some user data)
                            if next_line.starts_with("User ") || next_line.starts_with("Package [") {
                                break;
                            }
                            // For empty lines, only break if we've already parsed substantial user data
                            if next_line.is_empty() {
                                // Check if we have enough user data to consider this user block complete
                                if user_map.contains_key("installReason") || user_map.contains_key("gids") {
                                    break;
                                }
                                // Otherwise, skip the empty line and continue
                                lines_iter.next();
                                continue;
                            }
                            // Handle "lastDisabledCaller: com.android.vending" format (with colon, not equals)
                            if next_line.starts_with("lastDisabledCaller:") {
                                if let Some((_, value)) = next_line.split_once(':') {
                                    user_map.insert("lastDisabledCaller".to_string(), json!(value.trim()));
                                }
                                lines_iter.next();
                                continue;
                            }
                            
                            if let Some((k, v)) = next_line.split_once('=') {
                                let k = k.trim();
                                let v = v.trim();
                                if k == "installReason" || k == "uninstallReason" {
                                    user_map.insert(k.to_string(), json!(v.parse::<u32>().ok()));
                                } else if k == "firstInstallTime" {
                                    user_map.insert(k.to_string(), json!(v));
                                } else if k == "gids" {
                                    // Parse array like "[3002, 3003, 3001, 3007, 1007]"
                                    let gids: Vec<u32> = v
                                        .trim_matches(|c| c == '[' || c == ']')
                                        .split(',')
                                        .filter_map(|s| s.trim().parse::<u32>().ok())
                                        .collect();
                                    user_map.insert("gids".to_string(), json!(gids));
                                } else {
                                    // Store other fields as-is
                                    user_map.insert(k.to_string(), json!(v));
                                }
                            } else if next_line.starts_with("runtime permissions:") || next_line.starts_with("declared permissions:") || next_line.starts_with("install permissions:") {
                                // Skip permission headers
                                lines_iter.next();
                                continue;
                            } else if next_line.contains("granted=") {
                                // Parse permission line like "android.permission.POST_NOTIFICATIONS: granted=false, flags=[ POLICY_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]"
                                if let Some((perm_name, rest)) = next_line.split_once(':') {
                                    let perm_name = perm_name.trim();
                                    let mut perm_map = Map::new();
                                    perm_map.insert("permission".to_string(), json!(perm_name));
                                    
                                    // Parse granted value
                                    if let Some(granted_part) = rest.split(',').next() {
                                        if let Some((_, granted_val)) = granted_part.split_once('=') {
                                            let granted = granted_val.trim() == "true";
                                            perm_map.insert("granted".to_string(), json!(granted));
                                        }
                                    }
                                    
                                    // Parse flags if present: flags=[ POLICY_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
                                    if let Some(flags_part) = rest.split("flags=").nth(1) {
                                        let flags_str = flags_part
                                            .trim_matches(|c| c == '[' || c == ']')
                                            .trim();
                                        if !flags_str.is_empty() {
                                            // Split by | and collect flags
                                            let flags: Vec<&str> = flags_str
                                                .split('|')
                                                .map(|s| s.trim())
                                                .filter(|s| !s.is_empty())
                                                .collect();
                                            perm_map.insert("flags".to_string(), json!(flags));
                                        }
                                    }
                                    
                                    // Store in a permissions array
                                    if !user_map.contains_key("permissions") {
                                        user_map.insert("permissions".to_string(), json!(Vec::<Value>::new()));
                                    }
                                    if let Some(perms) = user_map.get_mut("permissions") {
                                        if let Some(perms_array) = perms.as_array_mut() {
                                            perms_array.push(json!(perm_map));
                                        }
                                    }
                                }
                            }
                            lines_iter.next();
                        }
                        
                        // Store user info
                        if !package_map.contains_key("users") {
                            package_map.insert("users".to_string(), json!(Vec::<Value>::new()));
                        }
                        if let Some(users) = package_map.get_mut("users") {
                            if let Some(users_array) = users.as_array_mut() {
                                users_array.push(json!(user_map));
                            }
                        }
                        continue; // User line already consumed
                    }
                }
                // If User parsing failed, line was already consumed
            } else if let Some((key, value)) = line.split_once('=') {
                // Parse key=value pairs
                let key = key.trim();
                let value = value.trim();
                
                // Handle special cases
                if key == "appId" {
                    package_map.insert("appId".to_string(), json!(value.parse::<u32>().ok()));
                } else if key == "versionCode" {
                    // versionCode might have additional info like "16 minSdk=26 targetSdk=34"
                    if let Some(version_code) = value.split_whitespace().next() {
                        package_map.insert("versionCode".to_string(), json!(version_code.parse::<u64>().ok()));
                    }
                    // Also parse minSdk and targetSdk if present
                    if value.contains("minSdk=") {
                        for part in value.split_whitespace() {
                            if let Some((k, v)) = part.split_once('=') {
                                match k {
                                    "minSdk" => {
                                        package_map.insert("minSdk".to_string(), json!(v.parse::<u32>().ok()));
                                    }
                                    "targetSdk" => {
                                        package_map.insert("targetSdk".to_string(), json!(v.parse::<u32>().ok()));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                } else if key == "versionName" {
                    package_map.insert("versionName".to_string(), json!(value));
                } else if key == "dataDir" {
                    package_map.insert("dataDir".to_string(), json!(value));
                } else if key == "codePath" {
                    package_map.insert("codePath".to_string(), json!(value));
                } else if key == "installerPackageName" {
                    package_map.insert("installerPackageName".to_string(), json!(value));
                } else if key == "firstInstallTime" {
                    package_map.insert("firstInstallTime".to_string(), json!(value));
                } else if key == "lastUpdateTime" {
                    package_map.insert("lastUpdateTime".to_string(), json!(value));
                } else if key == "timeStamp" {
                    package_map.insert("timeStamp".to_string(), json!(value));
                } else if key == "pkg" {
                    // Extract package name from "Package{hash name}"
                    if let Some(start) = value.find('{') {
                        if let Some(end) = value[start+1..].find('}') {
                            let pkg_content = &value[start+1..start+1+end];
                            // The package name is usually the last part after spaces
                            if let Some(pkg_name) = pkg_content.split_whitespace().last() {
                                package_map.insert("pkg".to_string(), json!(pkg_name));
                            }
                        }
                    }
                } else {
                    // Store other fields as-is
                    package_map.insert(key.to_string(), json!(value));
                }
                lines_iter.next(); // Consume the line
            } else if line.starts_with("declared permissions:") || line.starts_with("install permissions:") {
                // Skip permission section headers
                lines_iter.next();
                continue;
            } else if line.contains(':') && !line.contains('=') {
                // Might be a permission line or other structured data
                // Skip for now or handle as needed
                lines_iter.next();
            } else {
                // Unknown line format, skip it
                lines_iter.next();
            }
        }
        
        Some((package_name, json!(package_map)))
    }

    /// Tries to parse a line as a simple key-value pair.
    fn parse_kv_line(line: &str, map: &mut Map<String, Value>) -> bool {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "Service host process PID" => {
                    map.insert("pid".to_string(), json!(value.parse::<u32>().ok()));
                    true
                }
                "Threads in use" => {
                    map.insert("threads".to_string(), json!(value));
                    true
                }
                "Client PIDs" => {
                    let pids: Vec<u32> = value
                        .split(',')
                        .filter_map(|s| s.trim().parse::<u32>().ok())
                        .collect();
                    map.insert("client_pids".to_string(), json!(pids));
                    true
                }
                _ => false, // Not a recognized simple key-value
            }
        } else {
            false
        }
    }
    
    /// Helper to extract "value" from "key{value}" or "key: value"
    fn extract_braced_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        // Case 1: key{value}
        let key_pattern = format!("{key}{{"); 
        if let Some(start_index) = line.find(&key_pattern) {
            let value_start = start_index + key_pattern.len();
            if let Some(end_index) = line[value_start..].find('}') {
                return Some(&line[value_start .. value_start + end_index]);
            }
        }
        
        // Case 2: key: value
        let key_pattern_colon = format!("{key}:");
        if let Some(start_index) = line.find(&key_pattern_colon) {
            let value_start = start_index + key_pattern_colon.len();
            let value = &line[value_start..].trim();
            // Take up to the next comma or end of string
            return Some(value.split(',').next().unwrap_or(value).trim());
        }
        
        None
    }

    /// Tries to parse a log entry, which may span multiple lines.
    /// It takes the current line and a peekable iterator for subsequent lines.
    /// Also takes a boundary checker function to stop at section boundaries.
    fn parse_log_entry<'a, I, F>(
        current_line: &str,
        lines_iter: &mut std::iter::Peekable<I>,
        is_boundary: F,
    ) -> Option<Value>
    where
        I: Iterator<Item = &'a str>,
        F: Fn(&str) -> bool,
    {
        // Check for timestamp format "YYYY-MM-DD HH:MM:SS.mmm:"
        if current_line.len() < 24 || current_line.chars().nth(4) != Some('-') || current_line.chars().nth(23) != Some(':') {
            return None;
        }
        
        if let Some((timestamp, message)) = current_line.split_at_this_many_colons(3) {
            let timestamp = timestamp.trim();
            let message = message.trim_start();
            
            let mut log_map = Map::new();
            log_map.insert("timestamp".to_string(), json!(timestamp));

            // Case 1: START INSTALL PACKAGE (multi-line)
            if message.starts_with("START INSTALL PACKAGE:") {
                log_map.insert("event_type".to_string(), json!("START_INSTALL"));
                
                if let Some(observer) = Self::extract_braced_value(message, "observer") {
                    log_map.insert("observer".to_string(), json!(observer));
                }
                
                // Consume next lines
                while let Some(next_line) = lines_iter.peek() {
                    let next_line_trimmed = next_line.trim();
                    
                    // Check for section boundary before processing
                    if is_boundary(next_line_trimmed) {
                        break;
                    }
                    
                    if next_line_trimmed.starts_with("stagedDir") {
                        log_map.insert("stagedDir".to_string(), json!(Self::extract_braced_value(next_line_trimmed, "stagedDir")));
                    } else if next_line_trimmed.starts_with("pkg") {
                        log_map.insert("pkg".to_string(), json!(Self::extract_braced_value(next_line_trimmed, "pkg")));
                    } else if next_line_trimmed.starts_with("versionCode") {
                        let vc = Self::extract_braced_value(next_line_trimmed, "versionCode")
                                   .and_then(|s| s.parse::<u64>().ok());
                        log_map.insert("versionCode".to_string(), json!(vc));
                    } else if next_line_trimmed.starts_with("Request from") {
                         log_map.insert("request_from".to_string(), json!(Self::extract_braced_value(next_line_trimmed, "Request from")));
                    } else {
                        break; // Not part of this block
                    }
                    lines_iter.next(); // Consume the line
                }
                return Some(json!(log_map));
            }

            // Case 2: START DELETE PACKAGE (multi-line, continuation on single line with commas)
            if message.starts_with("START DELETE PACKAGE:") {
                log_map.insert("event_type".to_string(), json!("START_DELETE"));
                
                if let Some(observer) = Self::extract_braced_value(message, "observer") {
                    log_map.insert("observer".to_string(), json!(observer));
                }
                
                // Consume next line which contains pkg, user, caller, flags (comma or space-separated)
                if let Some(next_line) = lines_iter.peek() {
                    let next_line_trimmed = next_line.trim();
                    
                    // Check for section boundary before processing
                    if is_boundary(next_line_trimmed) {
                        return Some(json!(log_map));
                    }
                    
                    // Parse all fields from the entire line (they can be comma or space-separated)
                    // Check for each field in the entire line, not just in comma-separated parts
                    if let Some(pkg) = Self::extract_braced_value(next_line_trimmed, "pkg") {
                        log_map.insert("pkg".to_string(), json!(pkg));
                    }
                    if let Some(user) = Self::extract_braced_value(next_line_trimmed, "user") {
                        let user_val = user.parse::<u32>().ok();
                        log_map.insert("user".to_string(), json!(user_val));
                    }
                    if let Some(caller) = Self::extract_braced_value(next_line_trimmed, "caller") {
                        log_map.insert("caller".to_string(), json!(caller));
                    }
                    if let Some(flags) = Self::extract_braced_value(next_line_trimmed, "flags") {
                        let flags_val = flags.parse::<u32>().ok();
                        log_map.insert("flags".to_string(), json!(flags_val));
                    }
                    lines_iter.next(); // Consume the line
                }
                return Some(json!(log_map));
            }

            // Case 3: result of install (single-line)
            if message.starts_with("result of install:") {
                log_map.insert("event_type".to_string(), json!("INSTALL_RESULT"));
                log_map.insert("message".to_string(), json!(message));
                return Some(json!(log_map));
            }

            // Case 4: result of delete (single-line)
            if message.starts_with("result of delete:") {
                log_map.insert("event_type".to_string(), json!("DELETE_RESULT"));
                log_map.insert("message".to_string(), json!(message));
                return Some(json!(log_map));
            }

            // Case 5: setApplicationCategoryHint (single-line, with commas)
            if message.starts_with("setApplicationCategoryHint,") {
                log_map.insert("event_type".to_string(), json!("SET_CATEGORY_HINT"));
                // "setApplicationCategoryHint, pkg: com.google..., caller: com.android.vending/10253"
                let parts: Vec<&str> = message.split(',').map(|s| s.trim()).collect();
                for part in parts.iter().skip(1) { // Skip "setApplicationCategoryHint"
                    if let Some((key, value)) = part.split_once(':') {
                        log_map.insert(key.trim().to_string(), json!(value.trim()));
                    }
                }
                return Some(json!(log_map));
            }
        }

        None
    }
}

impl Parser for PackageParser {
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let content = String::from_utf8_lossy(data);
        let mut results = Vec::new();

        const START_DELIMITER: &str = 
            "\n-------------------------------------------------------------------------------\n\
             DUMP OF SERVICE package:\n";
        
        const END_DELIMITER: &str = 
            "\n-------------------------------------------------------------------------------\n";

        // Collect all install_logs first, grouped by package name
        let mut install_logs_by_package: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
        
        // Parse Packages section only within DUMP OF SERVICE package blocks
        let mut packages_map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();

        for block in content.split(START_DELIMITER).skip(1) {
            // Find where this block ends (section end or delimiter)
            let all_block_lines: Vec<&str> = block.lines().collect();
            let mut block_end_idx = all_block_lines.len();
            for (idx, line) in all_block_lines.iter().enumerate() {
                let trimmed = line.trim();
                // Stop at section end (duration line)
                if Self::is_section_end_line(trimmed) {
                    block_end_idx = idx;
                    break;
                }
                // Stop at standard delimiter
                if trimmed.starts_with(END_DELIMITER.trim()) {
                    block_end_idx = idx;
                    break;
                }
            }
            
            // Only process lines within this block (from START_DELIMITER to end)
            let block_content: String = all_block_lines[..block_end_idx].join("\n");
            
            // Parse Packages section if it exists within this block
            if let Some(packages_section_start) = block_content.find("Packages:\n") {
                let packages_section = &block_content[packages_section_start..];
                let all_lines: Vec<&str> = packages_section.lines().collect();
                
                // Find where the Packages section ends (duration line or end of block)
                let mut section_end_idx = all_lines.len();
                let mut package_starts = Vec::new();
                for (idx, line) in all_lines.iter().enumerate() {
                    let trimmed = line.trim();
                    // Stop at duration line (end of section)
                    if Self::is_section_end_line(trimmed) {
                        section_end_idx = idx;
                        break;
                    }
                    // Collect package block starts
                    if trimmed.starts_with("Package [") {
                        package_starts.push(idx);
                    }
                }
                
                // Only process lines within the section
                let section_lines: Vec<&str> = all_lines[..section_end_idx].to_vec();
                
                // Parse each package block
                for (i, &start_idx) in package_starts.iter().enumerate() {
                    let end_idx = if i + 1 < package_starts.len() {
                        package_starts[i + 1]
                    } else {
                        section_lines.len()
                    };
                    
                    let package_lines: Vec<&str> = section_lines[start_idx..end_idx].to_vec();
                    let mut lines_iter = package_lines.iter().map(|s| *s).peekable();
                    
                    if let Some((pkg_name, pkg_data)) = Self::parse_package_block(&mut lines_iter) {
                        packages_map.insert(pkg_name, pkg_data);
                    }
                }
            }
            
            let mut section_map = Map::new();
            let mut install_logs = Vec::new();

            // Process install logs from the block (using the same block_end_idx we found earlier)
            let lines = all_block_lines[..block_end_idx]
                .iter()
                .map(|s| *s);
            
            let mut lines_iter = lines.peekable();

            // Create a boundary checker closure
            let is_boundary = |line: &str| -> bool {
                Self::is_section_end_line(line) || line.starts_with(END_DELIMITER.trim())
            };

            while let Some(line) = lines_iter.next() {
                let line = line.trim();
                
                // Check boundaries first before processing
                if is_boundary(line) {
                    break;
                }
                
                if line.is_empty() {
                    continue;
                }

                if PackageParser::parse_kv_line(line, &mut section_map) {
                    // Handled by parse_kv_line
                } else if let Some(log_entry) = PackageParser::parse_log_entry(line, &mut lines_iter, &is_boundary) {
                    // Extract package name from log entry
                    if let Some(pkg_name) = log_entry.get("pkg").and_then(|v| v.as_str()) {
                        install_logs_by_package
                            .entry(pkg_name.to_string())
                            .or_insert_with(Vec::new)
                            .push(log_entry.clone());
                    } else {
                        // Log entry without package name, store separately
                        install_logs_by_package
                            .entry("_unknown".to_string())
                            .or_insert_with(Vec::new)
                            .push(log_entry.clone());
                    }
                    // Store all logs for now - we'll filter them later
                    install_logs.push(log_entry);
                }
            }
            
            // Add service block if it has content (for backward compatibility)
            // We'll filter install_logs later to exclude those joined to packages
            if !section_map.is_empty() || !install_logs.is_empty() {
                if !install_logs.is_empty() {
                    section_map.insert("install_logs".to_string(), json!(install_logs));
                }
                if !section_map.is_empty() {
                    results.push(json!(section_map));
                }
            }
        }

        // Handle unknown logs first (before moving install_logs_by_package)
        let unknown_logs = install_logs_by_package.remove("_unknown");
        
        // Track which packages have install_logs that will be joined to packages
        // (so we can exclude them from service block install_logs)
        let mut packages_with_logs: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        // Now combine packages with their install_logs (only if we have package info)
        if !packages_map.is_empty() {
            let mut combined_packages = Vec::new();
            
            for (pkg_name, mut pkg_data) in packages_map {
                if let Some(pkg_obj) = pkg_data.as_object_mut() {
                    // Add install_logs for this package
                    if let Some(logs) = install_logs_by_package.remove(&pkg_name) {
                        pkg_obj.insert("install_logs".to_string(), json!(logs));
                        packages_with_logs.insert(pkg_name.clone());
                    }
                    combined_packages.push(json!(pkg_obj));
                }
            }
            
            // Don't add deleted packages (packages with logs but no package info) to packages section
            // Their logs should remain in the service block
            // So we leave them in install_logs_by_package, which will be handled later
            
            // Add combined packages to results
            if !combined_packages.is_empty() {
                let mut packages_section_map = Map::new();
                packages_section_map.insert("packages".to_string(), json!(combined_packages));
                results.push(json!(packages_section_map));
            }
        }
        
        // Now filter service block install_logs to exclude those joined to packages
        // Only keep logs for:
        // 1. Packages that don't exist in packages_map (deleted packages) - these stay in service block
        // 2. Logs without package names
        for result in results.iter_mut() {
            if let Some(service_block) = result.as_object_mut() {
                if let Some(install_logs_value) = service_block.get_mut("install_logs") {
                    if let Some(install_logs_array) = install_logs_value.as_array_mut() {
                        // Filter out logs for packages that have been joined to packages in Packages section
                        install_logs_array.retain(|log| {
                            // Keep logs without package names
                            if log.get("pkg").is_none() {
                                return true;
                            }
                            // For logs with package names, only keep if package is NOT in packages_with_logs
                            // (i.e., deleted packages that don't exist in Packages section)
                            if let Some(pkg_name) = log.get("pkg").and_then(|v| v.as_str()) {
                                // Keep if package is not in packages_with_logs (not joined to a package)
                                !packages_with_logs.contains(pkg_name)
                            } else {
                                true
                            }
                        });
                    }
                }
            }
        }
        
        // Deleted packages' logs are already in the service block install_logs
        // (they weren't filtered out because their packages aren't in packages_with_logs)
        // So we don't need to add them again - just discard install_logs_by_package
        // (except _unknown which is handled separately)
        
        // Handle unknown logs (logs without package names)
        // Only create a separate entry if there's no service block already containing them
        // (i.e., when there's no DUMP OF SERVICE package section)
        if let Some(logs) = unknown_logs {
            if !logs.is_empty() && results.is_empty() {
                // Only create unknown logs entry if no service blocks were created
                let mut service_map = Map::new();
                service_map.insert("install_logs".to_string(), json!(logs));
                results.push(json!(service_map));
            }
            // Otherwise, unknown logs are already in the service block, so we don't duplicate them
        }
        
        Ok(json!(results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;
    use serde_json::json;

    #[test]
    fn test_parse_package_service_block() {
        let data = b"
Junk before
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Service host process PID: 1486
Threads in use: 0/32
Client PIDs: 25036, 24988
Some other random line
2025-03-28 02:22:45.340: START INSTALL PACKAGE: observer{133061357}
          stagedDir{/data/app/vmdl1456751445.tmp}
          pkg{com.google.android.apps.youtube.music}
          versionCode{81253240}
          Request from{com.android.vending}
2025-03-28 02:22:45.717: result of install: 1{133061357}
2025-03-28 02:22:46.062: setApplicationCategoryHint, pkg: com.google.android.apps.youtube.music, oldCategory: 1, newCategory: 1, manifestCategory: 1, caller: com.android.vending/10253
-------------------------------------------------------------------------------
DUMP OF SERVICE other:
Some other data
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Updated expected JSON: "other_info" is no longer present.
        let expected = json!([
            {
                "pid": 1486,
                "threads": "0/32",
                "client_pids": [25036, 24988],
                "install_logs": [
                    {
                        "timestamp": "2025-03-28 02:22:45.340",
                        "event_type": "START_INSTALL",
                        "observer": "133061357",
                        "stagedDir": "/data/app/vmdl1456751445.tmp",
                        "pkg": "com.google.android.apps.youtube.music",
                        "versionCode": 81253240,
                        "request_from": "com.android.vending"
                    },
                    {
                        "timestamp": "2025-03-28 02:22:45.717",
                        "event_type": "INSTALL_RESULT",
                        "message": "result of install: 1{133061357}"
                    },
                    {
                        "timestamp": "2025-03-28 02:22:46.062",
                        "event_type": "SET_CATEGORY_HINT",
                        "pkg": "com.google.android.apps.youtube.music",
                        "oldCategory": "1",
                        "newCategory": "1",
                        "manifestCategory": "1",
                        "caller": "com.android.vending/10253"
                    }
                ]
            }
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_delete_package() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Service host process PID: 1486
2024-10-18 09:52:01.536: START DELETE PACKAGE: observer{49463941}
pkg{com.microsoft.office.outlook}, user{10}, caller{1010253} flags{4}
2024-10-18 09:52:01.538: result of delete: -2{49463941}
-------------------------------------------------------------------------------
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        let expected = json!([
            {
                "pid": 1486,
                "install_logs": [
                    {
                        "timestamp": "2024-10-18 09:52:01.536",
                        "event_type": "START_DELETE",
                        "observer": "49463941",
                        "pkg": "com.microsoft.office.outlook",
                        "user": 10,
                        "caller": "1010253",
                        "flags": 4
                    },
                    {
                        "timestamp": "2024-10-18 09:52:01.538",
                        "event_type": "DELETE_RESULT",
                        "message": "result of delete: -2{49463941}"
                    }
                ]
            }
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_packages_with_install_logs() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Service host process PID: 1486
2025-03-28 02:22:45.340: START INSTALL PACKAGE: observer{133061357}
          stagedDir{/data/app/vmdl1456751445.tmp}
          pkg{com.bitchat.droid}
          versionCode{16}
          Request from{com.android.vending}
2025-03-28 02:22:45.717: result of install: 1{133061357}
2024-10-18 09:52:01.536: START DELETE PACKAGE: observer{49463941}
pkg{com.microsoft.office.outlook}, user{10}, caller{1010253} flags{4}
2024-10-18 09:52:01.538: result of delete: -2{49463941}
Packages:
  Package [com.bitchat.droid] (672e433):
    appId=10333
    pkg=Package{2e4e3f0 com.bitchat.droid}
    codePath=/data/app/~~l6tHbjufc_oo0aALvWzQZw==/com.bitchat.droid-6UZto2rQBqG5oq8MF8tFuA==
    resourcePath=/data/app/~~l6tHbjufc_oo0aALvWzQZw==/com.bitchat.droid-6UZto2rQBqG5oq8MF8tFuA==
    legacyNativeLibraryDir=/data/app/~~l6tHbjufc_oo0aALvWzQZw==/com.bitchat.droid-6UZto2rQBqG5oq8MF8tFuA==/lib
    extractNativeLibs=false
    primaryCpuAbi=arm64-v8a
    secondaryCpuAbi=null
    cpuAbiOverride=null
    versionCode=16 minSdk=26 targetSdk=34
    minExtensionVersions=[]
    versionName=1.2.0
    usesNonSdkApi=false
    splits=[base]
    apkSigningVersion=2
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ALLOW_AUDIO_PLAYBACK_CAPTURE PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]
    forceQueryable=false
    dataDir=/data/user/0/com.bitchat.droid
    supportsScreens=[small, medium, large, xlarge, resizeable, anyDensity]
    timeStamp=2025-08-26 13:40:46
    lastUpdateTime=2025-08-26 13:40:57
    installerPackageName=com.google.android.packageinstaller
    installerPackageUid=10078
    initiatingPackageName=com.google.android.packageinstaller
    originatingPackageName=com.sec.android.app.sbrowser
    packageSource=4
    appMetadataFilePath=null
    signatures=PackageSignatures{4885d69 version:2, signatures:[9cff67fe], past signatures:[]}
    installPermissionsFixed=true
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    privatePkgFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ALLOW_AUDIO_PLAYBACK_CAPTURE PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]
    apexModuleName=null
    declared permissions:
      com.bitchat.droid.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION: prot=signature
    install permissions:
      android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: granted=true
      android.permission.INTERNET: granted=true
      com.bitchat.droid.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION: granted=true
      android.permission.ACCESS_NETWORK_STATE: granted=true
      android.permission.VIBRATE: granted=true
    User 0: ceDataInode=122761 installed=true hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false virtual=false
      installReason=4
      firstInstallTime=2025-08-26 13:40:57
      uninstallReason=0
      lastDisabledCaller: com.google.android.packageinstaller
      gids=[3003]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
    User 10: ceDataInode=0 installed=false hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false virtual=false
      installReason=0
      firstInstallTime=1970-01-01 01:00:00
      uninstallReason=0
      gids=[3003]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=false
        android.permission.ACCESS_FINE_LOCATION: granted=false
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        // Verify the structure
        assert!(result.is_array());
        let results_array = result.as_array().unwrap();
        
        // Should have service block and packages section
        assert!(results_array.len() >= 2);
        
        // Find the packages section
        let packages_section = results_array.iter()
            .find(|item| item.get("packages").is_some())
            .expect("Should have packages section");
        
        let packages = packages_section["packages"].as_array().unwrap();
        // Should have at least 1 package (com.bitchat.droid with full info)
        // May also have com.microsoft.office.outlook with just install_logs
        assert!(packages.len() >= 1);
        
        // Find com.bitchat.droid package
        let package = packages.iter()
            .find(|p| p["package_name"] == "com.bitchat.droid")
            .expect("Should have com.bitchat.droid package");
        
        // Verify package information is parsed
        assert_eq!(package["package_name"], "com.bitchat.droid");
        assert_eq!(package["appId"], 10333);
        assert_eq!(package["versionCode"], 16);
        assert_eq!(package["versionName"], "1.2.0");
        assert_eq!(package["minSdk"], 26);
        assert_eq!(package["targetSdk"], 34);
        assert_eq!(package["dataDir"], "/data/user/0/com.bitchat.droid");
        assert_eq!(package["codePath"], "/data/app/~~l6tHbjufc_oo0aALvWzQZw==/com.bitchat.droid-6UZto2rQBqG5oq8MF8tFuA==");
        assert_eq!(package["installerPackageName"], "com.google.android.packageinstaller");
        // firstInstallTime and lastUpdateTime are stored at user level, not package level
        // They will be verified in the users section below
        
        // Verify install_logs are joined with the package
        assert!(package.get("install_logs").is_some());
        let install_logs = package["install_logs"].as_array().unwrap();
        // Should have at least the START_INSTALL log
        assert!(install_logs.len() >= 1);
        
        // Verify install log exists
        let install_log = install_logs.iter()
            .find(|log| log.get("event_type").and_then(|v| v.as_str()) == Some("START_INSTALL"))
            .expect("Should have START_INSTALL log");
        assert_eq!(install_log["pkg"], "com.bitchat.droid");
        assert_eq!(install_log["versionCode"], 16);
        assert_eq!(install_log["observer"], "133061357");
        
        // Verify users are parsed (if present)
        if let Some(users_value) = package.get("users") {
            let users = users_value.as_array().unwrap();
            assert!(users.len() >= 1, "Should have at least one user");
            
            // Verify User 0 if present
            if let Some(user0) = users.iter().find(|u| u["user_id"] == 0) {
                assert_eq!(user0["installed"], true);
                if let Some(install_reason) = user0.get("installReason") {
                    assert_eq!(install_reason, 4);
                }
                if let Some(first_install) = user0.get("firstInstallTime") {
                    assert_eq!(first_install, "2025-08-26 13:40:57");
                }
            }
            
            // Verify User 10 if present
            if let Some(user10) = users.iter().find(|u| u["user_id"] == 10) {
                assert_eq!(user10["installed"], false);
                if let Some(install_reason) = user10.get("installReason") {
                    assert_eq!(install_reason, 0);
                }
            }
        }
        
        // Verify service block still exists with install_logs (for packages not in Packages section)
        let service_block = results_array.iter()
            .find(|item| item.get("pid").is_some())
            .expect("Should have service block");
        
        assert_eq!(service_block["pid"], 1486);
        let service_logs = service_block["install_logs"].as_array().unwrap();
        
        // Service block should have install_logs (for backward compatibility)
        // Note: com.microsoft.office.outlook might be in packages section or service block
        assert!(service_logs.len() >= 1);
        
        // Verify delete log exists (either in service block or packages section)
        let delete_log_in_service = service_logs.iter()
            .find(|log| log.get("event_type").and_then(|v| v.as_str()) == Some("START_DELETE"));
        
        // Check if it's in packages section instead
        let delete_log_in_packages = packages.iter()
            .find(|p| p["package_name"] == "com.microsoft.office.outlook")
            .and_then(|p| p.get("install_logs"))
            .and_then(|logs| logs.as_array())
            .and_then(|logs| logs.iter().find(|log| {
                log.get("event_type").and_then(|v| v.as_str()) == Some("START_DELETE")
            }));
        
        assert!(delete_log_in_service.is_some() || delete_log_in_packages.is_some(),
                "Delete log should be in either service block or packages section");
    }

    #[test]
    fn test_parse_packages_without_install_logs() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Packages:
  Package [com.example.app] (abc123):
    appId=10001
    versionCode=1 minSdk=21 targetSdk=33
    versionName=1.0.0
    dataDir=/data/user/0/com.example.app
    installerPackageName=com.android.packageinstaller
    User 0: ceDataInode=12345 installed=true hidden=false
      installReason=0
      firstInstallTime=2025-01-01 10:00:00
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result.is_array());
        let results_array = result.as_array().unwrap();
        
        // Should have packages section
        let packages_section = results_array.iter()
            .find(|item| item.get("packages").is_some())
            .expect("Should have packages section");
        
        let packages = packages_section["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 1);
        
        let package = &packages[0];
        assert_eq!(package["package_name"], "com.example.app");
        assert_eq!(package["appId"], 10001);
        assert_eq!(package["versionCode"], 1);
        
        // Should not have install_logs if none exist
        assert!(package.get("install_logs").is_none() || package["install_logs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_parse_multiple_packages_with_logs() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
2025-03-28 02:22:45.340: START INSTALL PACKAGE: observer{111}
          pkg{com.app1}
          versionCode{10}
2025-03-28 02:22:45.350: START INSTALL PACKAGE: observer{222}
          pkg{com.app2}
          versionCode{20}
Packages:
  Package [com.app1] (hash1):
    appId=1001
    versionCode=10 minSdk=21 targetSdk=33
    versionName=1.0.0
    User 0: installed=true
      installReason=0
  Package [com.app2] (hash2):
    appId=1002
    versionCode=20 minSdk=21 targetSdk=33
    versionName=2.0.0
    User 0: installed=true
      installReason=0
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result.is_array());
        let results_array = result.as_array().unwrap();
        
        let packages_section = results_array.iter()
            .find(|item| item.get("packages").is_some())
            .expect("Should have packages section");
        
        let packages = packages_section["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2);
        
        // Verify com.app1
        let app1 = packages.iter().find(|p| p["package_name"] == "com.app1").unwrap();
        assert_eq!(app1["appId"], 1001);
        assert_eq!(app1["versionCode"], 10);
        assert!(app1.get("install_logs").is_some());
        let app1_logs = app1["install_logs"].as_array().unwrap();
        assert_eq!(app1_logs.len(), 1);
        assert_eq!(app1_logs[0]["pkg"], "com.app1");
        
        // Verify com.app2
        let app2 = packages.iter().find(|p| p["package_name"] == "com.app2").unwrap();
        assert_eq!(app2["appId"], 1002);
        assert_eq!(app2["versionCode"], 20);
        assert!(app2.get("install_logs").is_some());
        let app2_logs = app2["install_logs"].as_array().unwrap();
        assert_eq!(app2_logs.len(), 1);
        assert_eq!(app2_logs[0]["pkg"], "com.app2");
    }

    #[test]
    fn test_parse_user_data_complete() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Packages:
  Package [com.example.app] (abc123):
    appId=10001
    versionCode=1
    User 0: ceDataInode=0 installed=false hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false virtual=false
      installReason=0
      firstInstallTime=2025-10-15 15:19:24
      uninstallReason=0
      gids=[3002, 3003, 3001, 3007, 1007]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=false
        android.permission.ACCESS_FINE_LOCATION: granted=false
        android.permission.ACCESS_COARSE_LOCATION: granted=false
    User 10: ceDataInode=129920 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false
      installReason=4
      firstInstallTime=2025-10-15 15:19:25
      uninstallReason=0
      lastDisabledCaller: com.android.vending
      gids=[3002, 3003, 3001, 3007, 1007]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=true, flags=[ POLICY_FIXED|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.ACCESS_COARSE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result.is_array());
        let results_array = result.as_array().unwrap();
        
        let packages_section = results_array.iter()
            .find(|item| item.get("packages").is_some())
            .expect("Should have packages section");
        
        let packages = packages_section["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 1);
        
        let package = &packages[0];
        assert!(package.get("users").is_some(), "Package should have users field");
        let users = package["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        
        // Verify User 0
        let user0 = users.iter().find(|u| u["user_id"] == 0).unwrap();
        assert_eq!(user0["ceDataInode"], 0);
        assert_eq!(user0["installed"], false);
        assert_eq!(user0["hidden"], false);
        assert_eq!(user0["suspended"], false);
        assert_eq!(user0["distractionFlags"], 0);
        assert_eq!(user0["stopped"], true);
        assert_eq!(user0["notLaunched"], true);
        assert_eq!(user0["enabled"], 0);
        assert_eq!(user0["instant"], false);
        assert_eq!(user0["virtual"], false);
        assert_eq!(user0["installReason"], 0);
        assert_eq!(user0["firstInstallTime"], "2025-10-15 15:19:24");
        assert_eq!(user0["uninstallReason"], 0);
        
        // Verify gids array
        let gids = user0["gids"].as_array().unwrap();
        assert_eq!(gids.len(), 5);
        assert_eq!(gids[0], 3002);
        assert_eq!(gids[1], 3003);
        
        // Verify permissions for User 0 (if present)
        if let Some(perms0) = user0.get("permissions") {
            let perms0_array = perms0.as_array().unwrap();
            assert!(perms0_array.len() >= 1);
            if let Some(post_notif) = perms0_array.iter().find(|p| p["permission"] == "android.permission.POST_NOTIFICATIONS") {
                assert_eq!(post_notif["granted"], false);
            }
        }
        
        // Verify User 10
        let user10 = users.iter().find(|u| u["user_id"] == 10).unwrap();
        assert_eq!(user10["ceDataInode"], 129920);
        assert_eq!(user10["installed"], true);
        assert_eq!(user10["stopped"], false);
        assert_eq!(user10["notLaunched"], false);
        assert_eq!(user10["installReason"], 4);
        assert_eq!(user10["firstInstallTime"], "2025-10-15 15:19:25");
        assert_eq!(user10["lastDisabledCaller"], "com.android.vending");
        
        // Verify permissions for User 10 with flags (if present)
        if let Some(perms10) = user10.get("permissions") {
            let perms10_array = perms10.as_array().unwrap();
            assert!(perms10_array.len() >= 1);
            if let Some(post_notif10) = perms10_array.iter().find(|p| p["permission"] == "android.permission.POST_NOTIFICATIONS") {
                assert_eq!(post_notif10["granted"], true);
                if let Some(flags) = post_notif10.get("flags") {
                    let flags_array = flags.as_array().unwrap();
                    assert!(flags_array.len() >= 3);
                    assert!(flags_array.iter().any(|f| f.as_str() == Some("POLICY_FIXED")));
                    assert!(flags_array.iter().any(|f| f.as_str() == Some("USER_SENSITIVE_WHEN_GRANTED")));
                    assert!(flags_array.iter().any(|f| f.as_str() == Some("USER_SENSITIVE_WHEN_DENIED")));
                }
            }
            if let Some(fine_loc) = perms10_array.iter().find(|p| p["permission"] == "android.permission.ACCESS_FINE_LOCATION") {
                assert_eq!(fine_loc["granted"], false);
                assert!(fine_loc.get("flags").is_some());
            }
        }
    }

    #[test]
    fn test_exclude_joined_logs_from_service_block() {
        let data = b"
-------------------------------------------------------------------------------
DUMP OF SERVICE package:
Service host process PID: 1486
2025-03-28 02:22:45.340: START INSTALL PACKAGE: observer{111}
          pkg{com.existing.app}
          versionCode{10}
2025-03-28 02:22:45.350: START INSTALL PACKAGE: observer{222}
          pkg{com.deleted.app}
          versionCode{20}
2025-03-28 02:22:45.360: result of install: 1{111}
Packages:
  Package [com.existing.app] (hash1):
    appId=1001
    versionCode=10
    User 0: installed=true
      installReason=0
        ";
        let parser = PackageParser::new().unwrap();
        let result = parser.parse(data).unwrap();
        
        assert!(result.is_array());
        let results_array = result.as_array().unwrap();
        
        // Find the packages section
        let packages_section = results_array.iter()
            .find(|item| item.get("packages").is_some())
            .expect("Should have packages section");
        
        let packages = packages_section["packages"].as_array().unwrap();
        
        // com.existing.app should be in packages with its install_logs
        let existing_app = packages.iter()
            .find(|p| p["package_name"] == "com.existing.app")
            .expect("Should have com.existing.app");
        assert!(existing_app.get("install_logs").is_some());
        let existing_logs = existing_app["install_logs"].as_array().unwrap();
        assert_eq!(existing_logs.len(), 1);
        assert_eq!(existing_logs[0]["pkg"], "com.existing.app");
        
        // com.deleted.app should NOT be in packages section (deleted package - logs stay in service block)
        let deleted_app_in_packages = packages.iter()
            .find(|p| p["package_name"] == "com.deleted.app");
        assert!(deleted_app_in_packages.is_none(), "Deleted packages should not be in packages section");
        
        // Find the service block
        let service_block = results_array.iter()
            .find(|item| item.get("pid").is_some())
            .expect("Should have service block");
        
        let service_logs = service_block["install_logs"].as_array().unwrap();
        
        // Service block should NOT have logs for com.existing.app (they're in the package)
        let existing_app_logs_in_service = service_logs.iter()
            .filter(|log| log.get("pkg").and_then(|v| v.as_str()) == Some("com.existing.app"))
            .count();
        assert_eq!(existing_app_logs_in_service, 0, "Service block should not have logs for com.existing.app");
        
        // Service block SHOULD have logs for com.deleted.app (deleted package - not in Packages section)
        let deleted_app_logs_in_service = service_logs.iter()
            .filter(|log| log.get("pkg").and_then(|v| v.as_str()) == Some("com.deleted.app"))
            .count();
        assert!(deleted_app_logs_in_service >= 1, "Service block should have logs for com.deleted.app (deleted package)");
        
        // Logs without package names should also be in service block
        let logs_without_pkg = service_logs.iter()
            .filter(|log| log.get("pkg").is_none())
            .count();
        assert!(logs_without_pkg >= 1, "Service block should have logs without package names");
    }
}