// File loading utilities with ZIP support
// This module provides functions to load bugreport files, automatically handling ZIP archives
// NOTE: This module is only available for native builds (not WASM)
// For WASM, use the wasm_api module which works with byte arrays from JavaScript

#[cfg(not(target_arch = "wasm32"))]
use std::fs::File;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::error::Error;
#[cfg(not(target_arch = "wasm32"))]
use memmap2::Mmap;
#[cfg(not(target_arch = "wasm32"))]
use tracing::info;

#[cfg(not(target_arch = "wasm32"))]
use crate::zip_utils;

/// Loads a file into memory, automatically extracting dumpstate.txt if it's a ZIP file
/// 
/// This function:
/// 1. Memory-maps the file for efficient reading
/// 2. Checks if it's a ZIP file
/// 3. If ZIP: extracts dumpstate.txt into a Vec and returns it
/// 4. If plain text: returns the memory-mapped content
/// 
/// # Arguments
/// * `file_path` - Path to the bugreport file (.txt or .zip)
/// 
/// # Returns
/// * `Ok((Arc<[u8]>, bool))` - The file content and whether it was extracted from ZIP
/// * `Err` - If the file cannot be read or ZIP extraction fails
/// 
/// # Note
/// This function is only available for native builds (not WASM)
#[cfg(not(target_arch = "wasm32"))]
pub fn load_bugreport_file<P: AsRef<Path>>(
    file_path: P,
) -> Result<(Arc<[u8]>, bool), Box<dyn Error + Send + Sync>> {
    let file = File::open(&file_path)?;
    let file_size = file.metadata()?.len();
    
    // Memory-map the file
    // SAFETY: The file is not modified while the map is open
    let mmap = unsafe { Mmap::map(&file)? };
    
    // Check if this is a ZIP file
    if zip_utils::is_zip_file(&mmap) {
        info!("Detected ZIP file, extracting dumpstate.txt...");
        
        // Re-open the file for ZIP extraction (we need a seekable reader)
        let file_for_zip = File::open(&file_path)?;
        let dumpstate_content = zip_utils::extract_dumpstate_from_zip(file_for_zip)?;
        
        info!(
            "Extracted dumpstate.txt: {:.2} MB (original ZIP: {:.2} MB)",
            dumpstate_content.len() as f64 / 1_048_576.0,
            file_size as f64 / 1_048_576.0
        );
        
        Ok((Arc::from(dumpstate_content), true))
    } else {
        // Not a ZIP, use the memory-mapped content directly
        info!("Loading plain text file: {:.2} MB", file_size as f64 / 1_048_576.0);
        Ok((Arc::from(&mmap[..]), false))
    }
}

/// Determines the appropriate file description for progress messages
/// 
/// # Note
/// This function is only available for native builds (not WASM)
#[cfg(not(target_arch = "wasm32"))]
pub fn get_file_description(file_path: &str, is_zip: bool) -> String {
    if is_zip {
        format!("{} (extracted from ZIP)", file_path)
    } else {
        file_path.to_string()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_plain_text_file() {
        // Create a temporary plain text file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "This is a test bugreport").unwrap();
        writeln!(temp_file, "------ MEMORY INFO ------").unwrap();
        temp_file.flush().unwrap();
        
        let (content, is_zip) = load_bugreport_file(temp_file.path()).unwrap();
        
        assert!(!is_zip);
        assert!(content.len() > 0);
        
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("test bugreport"));
        assert!(text.contains("MEMORY INFO"));
    }
    
    #[test]
    fn test_load_zip_file() {
        use zip::write::FileOptions;
        
        // Create a temporary ZIP file
        let temp_file = NamedTempFile::new().unwrap();
        {
            let mut zip = zip::ZipWriter::new(&temp_file);
            
            zip.start_file("dumpstate.txt", FileOptions::default()).unwrap();
            writeln!(zip, "======== dumpstate content ========").unwrap();
            writeln!(zip, "------ MEMORY INFO ------").unwrap();
            writeln!(zip, "MemTotal: 8000000 kB").unwrap();
            
            zip.start_file("version.txt", FileOptions::default()).unwrap();
            writeln!(zip, "Version info").unwrap();
            
            zip.finish().unwrap();
        }
        
        let (content, is_zip) = load_bugreport_file(temp_file.path()).unwrap();
        
        assert!(is_zip);
        assert!(content.len() > 0);
        
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("dumpstate content"));
        assert!(text.contains("MEMORY INFO"));
        assert!(text.contains("MemTotal"));
        // Should NOT contain version.txt content
        assert!(!text.contains("Version info"));
    }
}