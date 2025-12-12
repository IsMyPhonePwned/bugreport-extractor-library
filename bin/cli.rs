use clap::Parser;
use std::error::Error;
use std::time::Instant;
use std::sync::Arc;
use std::fs::File;

use memmap2::Mmap;
use std::path::PathBuf;

use tracing::{info, warn};
use tracing_subscriber;

use sigma_zero::engine::SigmaEngine;

use bugreport_extractor_library::run_parsers_concurrently;
use bugreport_extractor_library::parsers::{
    Parser as DataParser, ParserType, HeaderParser, MemoryParser, BatteryParser, 
    PackageParser, ProcessParser, PowerParser, UsbParser
};
use bugreport_extractor_library::sigma_integration;
use bugreport_extractor_library::sigma_output::{should_output_match, output_match, output_match_with_log, SigmaStats};
use bugreport_extractor_library::progress::ProgressTracker;
use bugreport_extractor_library::comparison;
use std::collections::HashMap;

/// A command-line tool to parse large data files into JSON using multiple parsers concurrently.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The path to the input file to be processed (not needed in comparison mode)
    #[arg(short, long, required_unless_present = "compare")]
    file_path: Option<String>,

    /// The type of parser(s) to use. Can be specified multiple times.
    #[arg(short, long, value_enum, num_args = 1.., required_unless_present = "compare")]
    parser_type: Vec<ParserType>,

    /// Path to directory containing Sigma rules (YAML files)
    #[arg(short, long)]
    rules_dir: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Number of parallel workers (defaults to number of CPU cores)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Only show matches at or above this level (low, medium, high, critical)
    #[arg(short, long)]
    min_level: Option<String>,

    /// Output format: json, text, or silent
    #[arg(short, long, default_value = "text")]
    output_format: String,

    /// Skip Sigma rule evaluation (only parse and output data)
    #[arg(long)]
    no_sigma: bool,

    /// Show detailed log entry information with matches (displays specific fields from matched logs)
    #[arg(long)]
    show_log_details: bool,

    /// Disable progress indicators (useful for scripting or when output is redirected)
    #[arg(long)]
    no_progress: bool,

    /// Comparison mode: compare two bugreports (provide two file paths)
    #[arg(long, num_args = 2, value_names = &["BEFORE", "AFTER"])]
    compare: Option<Vec<String>>,
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    // Initialize progress tracker (disabled if no_progress flag or in silent mode)
    let show_progress = !args.no_progress && args.output_format != "silent" && !args.verbose;
    let progress = ProgressTracker::new(show_progress);

    // === COMPARISON MODE ===
    if let Some(compare_files) = &args.compare {
        if compare_files.len() != 2 {
            eprintln!("Error: --compare requires exactly 2 file paths");
            std::process::exit(1);
        }
        
        info!("Running in comparison mode");
        run_comparison_mode(&compare_files[0], &compare_files[1], &args, &progress)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e)))
            })?;
        return Ok(());
    }

    // === NORMAL MODE ===
    // Require file_path if not in comparison mode
    let file_path = args.file_path.as_ref().ok_or("--file-path is required")?;

    let start_time = Instant::now();

    // Initialize Sigma engine if rules directory provided and not skipped
    let mut engine_opt: Option<SigmaEngine> = None;
    if !args.no_sigma {
        if let Some(ref rules_dir) = args.rules_dir {
            let rule_pb = progress.create_rule_loading_progress();
            info!("Loading Sigma rules from {:?}...", rules_dir);
            
            let mut engine = SigmaEngine::new(args.workers);
            let rules_loaded = engine.load_rules(rules_dir)?;
            
            ProgressTracker::finish_with_message(
                rule_pb, 
                &format!("✓ Loaded {} Sigma rules", rules_loaded)
            );
            info!("Loaded {} Sigma rules", rules_loaded);
            engine_opt = Some(engine);
        } else {
            warn!("No rules directory provided. Use --rules-dir to enable Sigma detection.");
        }
    }

    // Create a list of parser instances based on command-line arguments.
    let mut parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = Vec::new();

    for pt in &args.parser_type {
        match pt {
            ParserType::Header => {
                let header_parser = HeaderParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(header_parser)));
            },
            ParserType::Memory => {
                let memory_parser = MemoryParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(memory_parser)));
            },
            ParserType::Battery => {
                let battery_parser = BatteryParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(battery_parser)));
            },
            ParserType::Package => {
                let package_parser = PackageParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(package_parser)));
            },
            ParserType::Process => {
                let process_parser = ProcessParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(process_parser)));
            },
            ParserType::Power => {
                let power_parser = PowerParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(power_parser)));
            },
            ParserType::Usb => {
                let usb_parser = UsbParser::new()?;
                parsers_to_run.push((pt.clone(), Box::new(usb_parser)));
            },
        }
    }

    if !show_progress {
        println!(
            "Processing file '{}' with {:?} parsers concurrently...",
            file_path, args.parser_type
        );
    }

    // Memory-map the file for efficient, concurrent reading.
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    
    // Show file loading progress
    let file_pb = progress.create_file_progress(file_size);
    
    // SAFETY: The file is not modified while the map is open, which is a requirement for memmap.
    let mmap = unsafe { Mmap::map(&file)? };
    
    ProgressTracker::set_position(&file_pb, file_size);
    ProgressTracker::finish_with_message(
        file_pb, 
        &format!("✓ Loaded {} ({:.2} MB)", file_path, file_size as f64 / 1_048_576.0)
    );

    // The file content is shared across threads using an Arc.
    let file_content: Arc<[u8]> = Arc::from(&mmap[..]);

    // Create progress bar for parser execution
    let parser_pb = progress.create_multi_parser_progress(parsers_to_run.len());

    // Process the file using all selected parsers in parallel.
    let results = run_parsers_concurrently(file_content, parsers_to_run);
    
    ProgressTracker::set_position(&parser_pb, results.len() as u64);
    ProgressTracker::finish_with_message(
        parser_pb,
        &format!("✓ All {} parsers completed in {:?}", results.len(), start_time.elapsed())
    );

    if !show_progress {
        println!(
            "\n--- All parsers finished in {:?} ---",
            start_time.elapsed()
        );
    }

    // Print the JSON result from each parser.
    for (parser_type, result, duration) in &results {
        println!("\n--- Results for {:?} parser (took: {:.2?}) ---", parser_type, duration);
        match result {
            Ok(json_output) => {
                // For brevity, we'll just print the number of top-level items.
                if let Some(arr) = json_output.as_array() {
                    println!("Successfully parsed {} records.", arr.len());
                } else {
                    println!("Successfully parsed a JSON object.");
                }
                // Uncomment the line below if you want to see the full JSON output.
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    // === Sigma Rule Evaluation ===
    if let Some(engine) = engine_opt {
        if !show_progress {
            println!("\n=== Starting Sigma Rule Evaluation ===\n");
        }
        
        let mut stats = SigmaStats::new();
        
        // Extract log entries from all parser results
        let all_entries = sigma_integration::extract_all_log_entries(&results);
        
        // Calculate total entries for progress tracking
        let total_entries: usize = all_entries.iter().map(|(_, entries)| entries.len()).sum();
        stats.total_logs_evaluated = total_entries;
        
        // Create overall progress bar
        let overall_pb = progress.create_sigma_progress(total_entries);
        
        // Evaluate each set of log entries
        for (parser_type, log_entries) in all_entries {
            if log_entries.is_empty() {
                continue;
            }
            
            info!(
                "Evaluating {} log entries from {:?} parser",
                log_entries.len(),
                parser_type
            );
            
            // Create per-parser progress bar
            let parser_pb = progress.create_parser_sigma_progress(
                &format!("{:?}", parser_type),
                log_entries.len()
            );
            
            for log_entry in log_entries {
                let matches = engine.evaluate_log_entry(&log_entry);
                
                for rule_match in matches {
                    if should_output_match(&rule_match, &args.min_level) {
                        // Use detailed output if flag is set
                        if args.show_log_details {
                            output_match_with_log(&rule_match, &log_entry, &args.output_format);
                        } else {
                            output_match(&rule_match, &args.output_format);
                        }
                        stats.record_match(&rule_match, &format!("{:?}", parser_type));
                    }
                }
                
                // Update progress bars
                ProgressTracker::inc(&parser_pb, 1);
                ProgressTracker::inc(&overall_pb, 1);
            }
            
            ProgressTracker::finish_and_clear(parser_pb);
        }
        
        ProgressTracker::finish_with_message(
            overall_pb,
            &format!("✓ Evaluated {} log entries, found {} matches", total_entries, stats.total_matches)
        );
        
        // Print summary unless in silent mode
        if args.output_format != "silent" {
            stats.print_summary();
        } else {
            println!("Total matches: {}", stats.total_matches);
        }
    }

    Ok(())
}

/// Run comparison mode: parse two files and compare them
fn run_comparison_mode(
    before_file: &str,
    after_file: &str,
    args: &Args,
    progress: &ProgressTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use memmap2::Mmap;
    use std::sync::Arc;
    
    info!("Comparing {} → {}", before_file, after_file);
    
    // Determine which parsers to use
    let parser_types = if args.parser_type.is_empty() {
        // Default: use Package, Process, USB, Power for comparison
        vec![ParserType::Package, ParserType::Process, ParserType::Usb, ParserType::Power]
    } else {
        args.parser_type.clone()
    };
    
    // Create parser instances for BEFORE file
    let mut parsers_before: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = Vec::new();
    for pt in &parser_types {
        match pt {
            ParserType::Header => {
                let parser = HeaderParser::new().expect("Failed to create HeaderParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Memory => {
                let parser = MemoryParser::new().expect("Failed to create MemoryParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Battery => {
                let parser = BatteryParser::new().expect("Failed to create BatteryParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Package => {
                let parser = PackageParser::new().expect("Failed to create PackageParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Process => {
                let parser = ProcessParser::new().expect("Failed to create ProcessParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Power => {
                let parser = PowerParser::new().expect("Failed to create PowerParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Usb => {
                let parser = UsbParser::new().expect("Failed to create UsbParser");
                parsers_before.push((pt.clone(), Box::new(parser)));
            },
        }
    }
    
    // Parse BEFORE file
    let before_pb = progress.create_file_progress(0);
    ProgressTracker::set_message(&before_pb, &format!("Loading before file: {}", before_file));
    
    let file = File::open(before_file)?;
    let file_size = file.metadata()?.len();
    let mmap = unsafe { Mmap::map(&file)? };
    let file_content: Arc<[u8]> = Arc::from(&mmap[..]);
    
    ProgressTracker::set_position(&before_pb, file_size);
    ProgressTracker::finish_with_message(
        before_pb,
        &format!("✓ Loaded {} ({:.2} MB)", before_file, file_size as f64 / 1_048_576.0)
    );
    
    let before_results = run_parsers_concurrently(file_content, parsers_before);
    
    // Create parser instances for AFTER file
    let mut parsers_after: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = Vec::new();
    for pt in &parser_types {
        match pt {
            ParserType::Header => {
                let parser = HeaderParser::new().expect("Failed to create HeaderParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Memory => {
                let parser = MemoryParser::new().expect("Failed to create MemoryParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Battery => {
                let parser = BatteryParser::new().expect("Failed to create BatteryParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Package => {
                let parser = PackageParser::new().expect("Failed to create PackageParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Process => {
                let parser = ProcessParser::new().expect("Failed to create ProcessParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Power => {
                let parser = PowerParser::new().expect("Failed to create PowerParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
            ParserType::Usb => {
                let parser = UsbParser::new().expect("Failed to create UsbParser");
                parsers_after.push((pt.clone(), Box::new(parser)));
            },
        }
    }
    
    // Parse AFTER file
    let after_pb = progress.create_file_progress(0);
    ProgressTracker::set_message(&after_pb, &format!("Loading after file: {}", after_file));
    
    let file = File::open(after_file)?;
    let file_size = file.metadata()?.len();
    let mmap = unsafe { Mmap::map(&file)? };
    let file_content: Arc<[u8]> = Arc::from(&mmap[..]);
    
    ProgressTracker::set_position(&after_pb, file_size);
    ProgressTracker::finish_with_message(
        after_pb,
        &format!("✓ Loaded {} ({:.2} MB)", after_file, file_size as f64 / 1_048_576.0)
    );
    
    let after_results = run_parsers_concurrently(file_content, parsers_after);
    
    // Convert results to HashMap for easier comparison
    let mut before_map: HashMap<ParserType, serde_json::Value> = HashMap::new();
    for (parser_type, result, _) in before_results {
        if let Ok(value) = result {
            before_map.insert(parser_type, value);
        }
    }
    
    let mut after_map: HashMap<ParserType, serde_json::Value> = HashMap::new();
    for (parser_type, result, _) in after_results {
        if let Ok(value) = result {
            after_map.insert(parser_type, value);
        }
    }
    
    // Perform comparison
    let comparison_pb = progress.create_parser_progress("Comparison");
    ProgressTracker::set_message(&comparison_pb, "🔍 Comparing outputs in parallel...");
    
    let comparison_result = comparison::compare_parser_outputs(
        &before_map,
        &after_map,
        before_file,
        after_file,
    );
    
    ProgressTracker::finish_with_message(
        comparison_pb,
        &format!("✓ Comparison complete - found {} changes across {} parsers", 
            comparison_result.total_changes(),
            comparison_result.parser_comparisons.len())
    );
    
    // Output comparison results
    comparison::output_comparison(&comparison_result, &args.output_format);
    
    Ok(())
}