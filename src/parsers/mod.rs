use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;

pub mod header_parser;
pub mod memory_parser;
pub mod battery_parser;
pub mod package_parser;
pub mod process_parser;
pub mod power_parser;
pub mod usb_parser;
pub mod crash_parser;
pub mod network_parser;
pub mod bluetooth_parser;
pub mod device_policy_parser;
pub mod adb_parser;
pub mod authentication_parser;
pub mod vpn_parser;

pub use header_parser::HeaderParser;
pub use memory_parser::MemoryParser;
pub use battery_parser::BatteryParser;
pub use package_parser::PackageParser;
pub use process_parser::ProcessParser;
pub use power_parser::PowerParser;
pub use usb_parser::UsbParser;
pub use crash_parser::CrashParser;
pub use network_parser::NetworkParser;
pub use bluetooth_parser::BluetoothParser;
pub use device_policy_parser::DevicePolicyParser;
pub use adb_parser::AdbParser;
pub use authentication_parser::AuthenticationParser;
pub use vpn_parser::VpnParser;

/// The core trait for all parsers.
/// Any new parser must implement this trait.
pub trait Parser {
    /// Parses a slice of bytes and returns a serde_json::Value.
    /// The error type must be Send + Sync to be used across threads.
    fn parse(&self, data: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>>;
}

/// Enum to represent the available parser types for command-line selection.
#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[cfg(not(target_arch = "wasm32"))]
pub enum ParserType {
    Header,
    Memory,
    Battery,
    Package,
    Process,
    Power,
    Usb,
    Crash,
    Network,
    Bluetooth,
    DevicePolicy,
    Adb,
    Authentication,
    Vpn
}

/// WASM-compatible parser type (without clap::ValueEnum)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[cfg(target_arch = "wasm32")]
pub enum ParserType {
    Header,
    Memory,
    Battery,
    Package,
    Process,
    Power,
    Usb,
    Crash,
    Network,
    Bluetooth,
    DevicePolicy,
    Adb,
    Authentication,
    Vpn
}

