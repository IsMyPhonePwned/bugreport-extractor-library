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
    // Try to find dumpstate.txt (case-insensitive search)
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_lowercase();
        
        // Check if this is the dumpstate file
        if name.contains("dumpstate.txt") || 
           (name.starts_with("bugreport-") && name.ends_with(".txt") && !name.contains("dumpstate_log")) {
            
            #[cfg(not(target_arch = "wasm32"))]
            tracing::info!("Found bugreport data in: {}", file.name());
            
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Found bugreport data in: {}", file.name()).into());
            
            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            
            return Ok(contents);
        }
    }
    
    // If we didn't find it by the above patterns, try the first large .txt
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name();
        
        // Look for any large .txt file (dumpstate.txt is typically several MB)
        if name.ends_with(".txt") && file.size() > 100_000 {
            #[cfg(not(target_arch = "wasm32"))]
            tracing::warn!("Using {} as dumpstate (couldn't find dumpstate.txt)", name);
            
            #[cfg(target_arch = "wasm32")]
            web_sys::console::warn_1(&format!("Using {} as dumpstate", name).into());
            
            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            
            return Ok(contents);
        }
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