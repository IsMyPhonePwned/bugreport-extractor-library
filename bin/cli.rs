use clap::Parser;
use std::error::Error;
use std::time::Instant;
use std::sync::Arc;
use std::fs::File;

use memmap2::Mmap;


use bugreport_extractor_library::run_parsers_concurrently;
use bugreport_extractor_library::parsers::{
    Parser as DataParser, ParserType, HeaderParser, MemoryParser, BatteryParser, PackageParser, ProcessParser
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
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

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
            }
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
                 println!("{}", serde_json::to_string_pretty(&json_output)?);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    Ok(())
}
