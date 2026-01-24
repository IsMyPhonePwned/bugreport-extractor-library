pub mod integration;
pub mod output;

pub use integration::extract_all_log_entries;
pub use output::{should_output_match, output_match, output_match_with_log, SigmaStats};
