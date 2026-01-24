// ZIP file handling utilities - WASM-compatible version
// This module handles ZIP extraction for both native and WASM targets

use std::io::{Read, Cursor};
use std::error::Error;

/// Checks if the given bytes represent a ZIP file by examining the magic bytes
/// Works on both native and WASM
pub fn is_zip_file(data: &[u8]) -> bool {
    // ZIP files start with PK\x03\x04 (0x50 0x4B 0x03 0x04)
    data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04
}

// ============================================================================
// NATIVE IMPLEMENTATION (using std::fs)
// ============================================================================

#[cfg(not(target_arch = "wasm32"))]
use std::io::Seek;

#[cfg(not(target_arch = "wasm32"))]
use zip::ZipArchive;

#[cfg(not(target_arch = "wasm32"))]
pub fn extract_dumpstate_from_zip<R: Read + Seek>(
    reader: R,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut archive = ZipArchive::new(reader)?;
    extract_dumpstate_from_archive(&mut archive)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn extract_dumpstate_from_zip_bytes(
    zip_data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let cursor = Cursor::new(zip_data);
    extract_dumpstate_from_zip(cursor)
}

// ============================================================================
// WASM IMPLEMENTATION (using in-memory data)
// ============================================================================

#[cfg(target_arch = "wasm32")]
use zip::ZipArchive;

/// Extract dumpstate from ZIP file bytes (WASM version)
/// Works with in-memory data only
#[cfg(target_arch = "wasm32")]
pub fn extract_dumpstate_from_zip_bytes(
    zip_data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor)?;
    extract_dumpstate_from_archive(&mut archive)
}

// ============================================================================
// SHARED IMPLEMENTATION (works on both native and WASM)
// ============================================================================

/// Extract dumpstate.txt from a ZipArchive
/// This works on both native and WASM because it only needs Read trait
fn extract_dumpstate_from_archive<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // First pass: Look for exact match "dumpstate.txt" (case-insensitive, ignoring path)
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name();
        let _name_lower = name.to_lowercase();
        
        // Extract just the filename (without path)
        let filename = name.split('/').last().unwrap_or(name);
        let filename_lower = filename.to_lowercase();
        
        // Check if this is exactly "dumpstate.txt" (ignoring path and case)
        if filename_lower == "dumpstate.txt" {
            #[cfg(not(target_arch = "wasm32"))]
            tracing::info!("Found dumpstate.txt: {}", name);
            
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Found dumpstate.txt: {}", name).into());
            
            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            
            return Ok(contents);
        }
    }
    
    // Second pass: Look for dumpstate-*.txt pattern (e.g., dumpstate-2026-01-21-11-06-58.txt)
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name();
        let _name_lower = name.to_lowercase();
        
        // Extract just the filename (without path)
        let filename = name.split('/').last().unwrap_or(name);
        let filename_lower = filename.to_lowercase();
        
        // Check if this matches dumpstate-*.txt pattern (but not dumpstate_log)
        if filename_lower.starts_with("dumpstate-") && 
           filename_lower.ends_with(".txt") && 
           !filename_lower.contains("dumpstate_log") &&
           !filename_lower.contains("dumpstate_debug") {
            #[cfg(not(target_arch = "wasm32"))]
            tracing::info!("Found dumpstate file: {}", name);
            
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Found dumpstate file: {}", name).into());
            
            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            
            return Ok(contents);
        }
    }
    
    // Third pass: Look for files containing "dumpstate.txt" in the name (but not dumpstate_log)
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name();
        let name_lower = name.to_lowercase();
        
        // Check if this is a dumpstate file (but not a log file)
        if name_lower.contains("dumpstate.txt") && !name_lower.contains("dumpstate_log") {
            #[cfg(not(target_arch = "wasm32"))]
            tracing::info!("Found bugreport data in: {}", name);
            
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Found bugreport data in: {}", name).into());
            
            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            
            return Ok(contents);
        }
    }
    
    // Fourth pass: Look for bugreport-*.txt files (but not dumpstate_log)
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name();
        let name_lower = name.to_lowercase();
        
        // Check for bugreport-*.txt pattern
        if name_lower.starts_with("bugreport-") && name_lower.ends_with(".txt") && !name_lower.contains("dumpstate_log") {
            #[cfg(not(target_arch = "wasm32"))]
            tracing::info!("Found bugreport file: {}", name);
            
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Found bugreport file: {}", name).into());
            
            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            
            return Ok(contents);
        }
    }
    
    // Fifth pass: Look for any large .txt file (dumpstate.txt is typically several MB)
    // Prefer files at the root level
    let mut candidates: Vec<(String, u64, usize)> = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let name = file.name();
        
        // Look for any large .txt file
        if name.ends_with(".txt") && file.size() > 100_000 {
            let depth = name.matches('/').count();
            candidates.push((name.to_string(), file.size(), depth));
        }
    }
    
    // Sort by depth (prefer root level) then by size (prefer larger files)
    candidates.sort_by(|a, b| {
        a.2.cmp(&b.2).then(b.1.cmp(&a.1))
    });
    
    if let Some((best_name, _, _)) = candidates.first() {
        // Re-open the file by name
        let mut file = archive.by_name(best_name)?;
        
        #[cfg(not(target_arch = "wasm32"))]
        tracing::warn!("Using {} as dumpstate (couldn't find dumpstate.txt)", best_name);
        
        #[cfg(target_arch = "wasm32")]
        web_sys::console::warn_1(&format!("Using {} as dumpstate", best_name).into());
        
        let mut contents = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut contents)?;
        
        return Ok(contents);
    }
    
    Err("Could not find dumpstate.txt or any suitable bugreport file in ZIP archive".into())
}

// ============================================================================
// WASM-BINDGEN EXPORTS
// ============================================================================

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn is_zip_file_wasm(data: &[u8]) -> bool {
    is_zip_file(data)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn extract_dumpstate_wasm(zip_data: &[u8]) -> Result<Vec<u8>, JsValue> {
    extract_dumpstate_from_zip_bytes(zip_data)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ============================================================================
// TESTS (work on both native and WASM with wasm-bindgen-test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zip_file() {
        // Valid ZIP magic bytes
        let zip_magic = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert!(is_zip_file(&zip_magic));
        
        // Invalid data
        let not_zip = vec![0x00, 0x00, 0x00, 0x00];
        assert!(!is_zip_file(&not_zip));
        
        // Text file
        let text = b"This is a text file";
        assert!(!is_zip_file(text));
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_extract_from_real_zip() {
        use std::io::Write;
        use zip::write::FileOptions;
        
        // Create a test ZIP in memory
        let mut zip_buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buffer);
            
            // Add some dummy files
            zip.start_file("version.txt", FileOptions::default()).unwrap();
            zip.write_all(b"Android version info").unwrap();
            
            // Add the dumpstate.txt we care about
            zip.start_file("dumpstate.txt", FileOptions::default()).unwrap();
            zip.write_all(b"========================================================\n\
                            == dumpstate: 2025-01-01 00:00:00\n\
                            ========================================================\n\
                            This is the dumpstate content\n\
                            ------ MEMORY INFO ------\n").unwrap();
            
            zip.start_file("dumpstate_log.txt", FileOptions::default()).unwrap();
            zip.write_all(b"Log file content").unwrap();
            
            zip.finish().unwrap();
        }
        
        // Extract dumpstate.txt
        let zip_data = zip_buffer.into_inner();
        let result = extract_dumpstate_from_zip_bytes(&zip_data).unwrap();
        let content = String::from_utf8_lossy(&result);
        
        assert!(content.contains("dumpstate content"));
        assert!(content.contains("MEMORY INFO"));
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_extract_dumpstate_with_date() {
        use std::io::Write;
        use zip::write::FileOptions;
        
        // Create a test ZIP with dumpstate-YYYY-MM-DD-HH-MM-SS.txt pattern
        let mut zip_buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_buffer);
            
            // Add some dummy files
            zip.start_file("version.txt", FileOptions::default()).unwrap();
            zip.write_all(b"Android version info").unwrap();
            
            // Add the dumpstate file with date pattern
            zip.start_file("dumpstate-2026-01-21-11-06-58.txt", FileOptions::default()).unwrap();
            zip.write_all(b"========================================================\n\
                            == dumpstate: 2026-01-21 11:06:58\n\
                            ========================================================\n\
                            This is the dumpstate content with date\n\
                            ------ MEMORY INFO ------\n").unwrap();
            
            zip.start_file("dumpstate_log.txt", FileOptions::default()).unwrap();
            zip.write_all(b"Log file content").unwrap();
            
            zip.finish().unwrap();
        }
        
        // Extract dumpstate file
        let zip_data = zip_buffer.into_inner();
        let result = extract_dumpstate_from_zip_bytes(&zip_data).unwrap();
        let content = String::from_utf8_lossy(&result);
        
        assert!(content.contains("dumpstate content with date"));
        assert!(content.contains("MEMORY INFO"));
        assert!(content.contains("2026-01-21"));
    }
}

// WASM-specific tests using wasm-bindgen-test
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_is_zip_file_wasm() {
        let zip_magic = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert!(is_zip_file_wasm(&zip_magic));
    }
}