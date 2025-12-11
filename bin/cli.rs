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
use sigma_zero::models::{LogEntry, RuleMatch};

use bugreport_extractor_library::run_parsers_concurrently;
use bugreport_extractor_library::parsers::{
    Parser as DataParser, ParserType, HeaderParser, MemoryParser, BatteryParser, PackageParser, ProcessParser, PowerParser, UsbParser
};

/// A command-line tool to parse large data files into JSON using multiple parsers concurrently.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The path to the input file to be processed
    #[arg(short, long)]
    file_path: String,

    /// The type of parser(s) to use. Can be specified multiple times.
    #[arg(short, long, value_enum, num_args = 1.., required = true)]
    parser_type: Vec<ParserType>,

    /// The regex pattern to use with the 'regex' parser type
    #[arg(long)]
    regex_pattern: Option<String>,

    /// Path to directory containing Sigma rules (YAML files)
    #[arg(short, long)]
    rules_dir: PathBuf,

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

    let mut engine = SigmaEngine::new(args.workers);

    info!("Loading Sigma rules...");
    let rules_loaded = engine.load_rules(&args.rules_dir)?;
    info!("Loaded {} Sigma rules", rules_loaded);

    let start_time = Instant::now();

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

    println!(
        "Processing file '{}' with {:?} parsers concurrently...",
        args.file_path, args.parser_type
    );

    
    // Memory-map the file for efficient, concurrent reading.
    let file = File::open(&args.file_path)?;
    // SAFETY: The file is not modified while the map is open, which is a requirement for memmap.
    let mmap = unsafe { Mmap::map(&file)? };

    // The file content is shared across threads using an Arc.
    let file_content: Arc<[u8]> = Arc::from(&mmap[..]);

    // Process the file using all selected parsers in parallel.
    let results = run_parsers_concurrently(file_content, parsers_to_run);

    println!(
        "\n--- All parsers finished in {:?} ---",
        start_time.elapsed()
    );

    // Print the JSON result from each parser.
    for (parser_type, result, duration) in results {
        println!("\n--- Results for {:?} parser (took: {:.2?}) ---", parser_type, duration);
        match result {
            Ok(json_output) => {
                // For brevity, we'll just print the number of top-level items.
                // Printing a huge JSON for a 200MB file would be slow.
                if let Some(arr) = json_output.as_array() {
                    println!("Successfully parsed {} records.", arr.len());
                } else {
                    println!("Successfully parsed a JSON object.");
                }
                // Uncomment the line below if you want to see the full JSON output.
                // println!("{}", serde_json::to_string_pretty(&json_output)?);

                // Convert each output to a valid Sigma Zero entry !
                if parser_type == ParserType::Package {
                    let first_array = json_output.as_array().unwrap();
                    if let Some(first_item) = first_array.get(0) {
                        // 2. Access the "install_logs" field and try to view it as an Array
                        if let Some(logs) = first_item["install_logs"].as_array() {
                            // 3. Iterate over the logs
                            for log_entry in logs {
                                let log_entry: LogEntry = match serde_json::from_str(&serde_json::to_string_pretty(&log_entry)?) {
                                        Ok(entry) => entry,
                                        Err(e) => {
                                            warn!("Failed to parse log line {}: ", e);
                                            continue;
                                        }
                                    };
                                    
                                    let matches = engine.evaluate_log_entry(&log_entry);
                                    for rule_match in matches {
                                        if should_output_match(&rule_match, &args.min_level) {
                                            output_match(&rule_match, &args.output_format);
                                        }
                                    }
                            }
                        } else {
                            println!("'install_logs' is missing or not an array");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    Ok(())
}


fn should_output_match(rule_match: &RuleMatch, min_level: &Option<String>) -> bool {
    if let Some(ref min) = min_level {
        if let Some(ref level) = rule_match.level {
            return level_priority(level) >= level_priority(min);
        }
        return false;
    }
    true
}

fn level_priority(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn output_match(rule_match: &RuleMatch, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(rule_match) {
                println!("{}", json);
            }
        }
        "silent" => {
            // No output, just count
        }
        _ => {
            // Text format (default)
            let level = rule_match.level.as_deref().unwrap_or("unknown");
            let level_icon = match level {
                "critical" => "🔥",
                "high" => "🚨",
                "medium" => "⚠️ ",
                "low" => "ℹ️ ",
                _ => "• ",
            };
            
            println!("{} [{}] {} ({})", 
                level_icon,
                level.to_uppercase(),
                rule_match.rule_title,
                rule_match.rule_id.as_deref().unwrap_or("unknown")
            );
        }
    }
}
