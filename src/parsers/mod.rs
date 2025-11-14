use serde_json::Value;
use std::error::Error;

mod header_parser;
mod memory_parser;
mod battery_parser;
mod package_parser;
mod process_parser;

pub use header_parser::HeaderParser;
pub use memory_parser::MemoryParser;
pub use battery_parser::BatteryParser;
pub use package_parser::PackageParser;
pub use process_parser::ProcessParser;


/// The core trait for all parsers.
/// Any new parser must implement this trait.
pub trait Parser {
    /// Parses a slice of bytes and returns a serde_json::Value.
    /// The error type must be Send + Sync to be used across threads.
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>>;
}

/// Enum to represent the available parser types for command-line selection.
#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ParserType {
    Header,
    Memory,
    Battery,
    Package,
    Process
}


