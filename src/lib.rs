use parsers::{Parser as DataParser, ParserType};
use serde_json::Value;
use std::error::Error;
use std::time::Instant;
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
pub mod progress;

// Re-export the modules so it can be accessed from main.rs
pub mod parsers;
pub mod sigma_integration;
pub mod sigma_output;
pub mod comparison;
pub mod detection;

/// Runs multiple parsers over the same file content concurrently using Rayon.
///
/// This function takes a shared reference to the file content (which can be a memory-mapped
/// region or a byte vector) and the list of parsers, and uses Rayon's parallel iterators
/// to run each parser on a thread pool.
///
/// # Arguments
///
/// * `file_content` - An `Arc<[u8]>` containing the raw bytes of the file to be parsed.
/// * `parsers_to_run` - A list of tuples, each containing a `ParserType` and a boxed parser instance.
///
/// # Returns
///
/// A vector of tuples, where each tuple contains the `ParserType`, the `Result` of the
/// parsing operation, and the `Duration` it took to complete.
pub fn run_parsers_concurrently(
    file_content: Arc<[u8]>,
    parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)>,
) -> Vec<(
    ParserType,
    Result<Value, Box<dyn Error + Send + Sync>>,
    std::time::Duration,
)> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Use Rayon's parallel iterator on native platforms
        parsers_to_run
            .into_par_iter()
            .map(|(parser_type, parser)| {
                let content_clone = Arc::clone(&file_content);
                let parser_start_time = Instant::now();
                let result = parser.parse(&content_clone);
                let duration = parser_start_time.elapsed();
                (parser_type, result, duration)
            })
            .collect()
    }
    
    #[cfg(target_arch = "wasm32")]
    {
        // Sequential processing for WASM
        parsers_to_run
            .into_iter()
            .map(|(parser_type, parser)| {
                let content_clone = Arc::clone(&file_content);
                let parser_start_time = Instant::now();
                let result = parser.parse(&content_clone);
                let duration = parser_start_time.elapsed();
                (parser_type, result, duration)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{Parser, ParserType};
    use serde_json::json;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct MockError(String);

    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for MockError {}

    // A mock parser that can be configured to either succeed or fail.
    struct MockParser {
        should_succeed: bool,
    }

    impl Parser for MockParser {
        fn parse(&self, _content: &[u8]) -> Result<Value, Box<dyn Error + Send + Sync>> {
            if self.should_succeed {
                Ok(json!({ "status": "ok" }))
            } else {
                Err(Box::new(MockError("Parsing failed as expected".into())))
            }
        }
    }

    #[test]
    fn test_run_parsers_concurrently_with_mock_parsers() {
        let file_content: Arc<[u8]> = Arc::from("some test data".as_bytes().to_vec());
        let parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = vec![
            (
                ParserType::Header, // Use a valid enum variant
                Box::new(MockParser {
                    should_succeed: false,
                }),
            ),
        ];

        let results = run_parsers_concurrently(file_content, parsers_to_run);

        assert_eq!(results.len(), 1, "Should return one result for the parser.");

        // Check the failing parser's result
        let failure_result = results
            .iter()
            .find(|(pt, _, _)| *pt == ParserType::Header)
            .unwrap();
        assert!(failure_result.1.is_err(), "The failing parser should return Err.");
        assert_eq!(
            failure_result.1.as_ref().unwrap_err().to_string(),
            "Parsing failed as expected"
        );
    }

    #[test]
    fn test_run_parsers_concurrently_success_and_failure() {
        let file_content: Arc<[u8]> = Arc::from("data".as_bytes().to_vec());
        let parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = vec![
            (
                ParserType::Memory,
                Box::new(MockParser {
                    should_succeed: true,
                }),
            ),
            (
                ParserType::Header,
                Box::new(MockParser {
                    should_succeed: false,
                }),
            ),
        ];

        let results = run_parsers_concurrently(file_content, parsers_to_run);

        assert_eq!(results.len(), 2, "Should return a result for each parser.");

        // Check the succeeding parser
        let success_result = results
            .iter()
            .find(|(pt, _, _)| *pt == ParserType::Memory)
            .unwrap();
        assert!(success_result.1.is_ok(), "The succeeding parser should return Ok.");
        assert_eq!(success_result.1.as_ref().unwrap(), &json!({ "status": "ok" }));

        // Check the failing parser
        let failure_result = results
            .iter()
            .find(|(pt, _, _)| *pt == ParserType::Header)
            .unwrap();
        assert!(failure_result.1.is_err(), "The failing parser should return Err.");
        assert_eq!(
            failure_result.1.as_ref().unwrap_err().to_string(),
            "Parsing failed as expected"
        );
    }

    #[test]
    fn test_empty_parser_list() {
        let file_content: Arc<[u8]> = Arc::from("".as_bytes().to_vec());
        let parsers_to_run: Vec<(ParserType, Box<dyn DataParser + Send + Sync>)> = vec![];

        let results = run_parsers_concurrently(file_content, parsers_to_run);

        assert!(results.is_empty(), "Result list should be empty when no parsers are provided.");
    }
}