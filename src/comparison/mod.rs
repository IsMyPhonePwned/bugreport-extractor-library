use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use crate::parsers::ParserType;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

// Submodules
mod package_differ;
mod process_differ;
mod usb_differ;
mod power_differ;
mod correlator;
mod output;

// Re-export key functions
pub use output::output_comparison;

/// Represents a change between two states
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Change {
    Added { item: Value },
    Removed { item: Value },
    Modified { before: Value, after: Value },
}

/// Comparison result for a single parser
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserComparison {
    pub parser_type: ParserType,
    pub added: Vec<Value>,
    pub removed: Vec<Value>,
    pub modified: Vec<(Value, Value)>,
    pub unchanged_count: usize,
}

impl ParserComparison {
    pub fn new(parser_type: ParserType) -> Self {
        Self {
            parser_type,
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
            unchanged_count: 0,
        }
    }
    
    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
    
    pub fn has_changes(&self) -> bool {
        self.total_changes() > 0
    }
}

/// Timeline event from any parser
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub parser: ParserType,
    pub event_type: String,
    pub change_type: String, // "added", "removed", "modified"
    pub details: Value,
}

/// Correlated suspicious activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub events: Vec<TimelineEvent>,
    pub correlation_type: String,
    pub description: String,
}

/// Overall comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub before_file: String,
    pub after_file: String,
    pub parser_comparisons: HashMap<ParserType, ParserComparison>,
    pub timeline_events: Vec<TimelineEvent>,
    pub correlations: Vec<Correlation>,
}

impl ComparisonResult {
    pub fn new(before_file: String, after_file: String) -> Self {
        Self {
            before_file,
            after_file,
            parser_comparisons: HashMap::new(),
            timeline_events: Vec::new(),
            correlations: Vec::new(),
        }
    }
    
    pub fn add_parser_comparison(&mut self, comparison: ParserComparison) {
        self.parser_comparisons.insert(comparison.parser_type.clone(), comparison);
    }
    
    pub fn total_changes(&self) -> usize {
        self.parser_comparisons.values().map(|c| c.total_changes()).sum()
    }
    
    pub fn has_changes(&self) -> bool {
        self.total_changes() > 0
    }
}

/// Compare two parser outputs and build a comprehensive comparison result
pub fn compare_parser_outputs(
    before: &HashMap<ParserType, Value>,
    after: &HashMap<ParserType, Value>,
    before_file: &str,
    after_file: &str,
) -> ComparisonResult {
    let mut result = ComparisonResult::new(before_file.to_string(), after_file.to_string());
    
    // Get all parser types from both files
    let mut all_parsers: Vec<ParserType> = before.keys().cloned().collect();
    all_parsers.extend(after.keys().cloned());
    
    // Remove duplicates while preserving order
    all_parsers.sort();
    all_parsers.dedup();
    
    // Compare each parser type IN PARALLEL
    #[cfg(not(target_arch = "wasm32"))]
    let comparisons_and_events: Vec<(ParserComparison, Vec<TimelineEvent>)> = all_parsers
        .par_iter()
        .filter_map(|parser_type| {
                     compare_parser_type(parser_type, before, after)            
        })
        .collect();
    
    #[cfg(target_arch = "wasm32")]
    let comparisons_and_events: Vec<(ParserComparison, Vec<TimelineEvent>)> = all_parsers
        .iter()
        .filter_map(|parser_type| {
            compare_parser_type(parser_type, before, after)
        })
        .collect();
    
    // Collect results (must be done sequentially to maintain data structure)
    for (comparison, events) in comparisons_and_events {
        result.timeline_events.extend(events);
        result.add_parser_comparison(comparison);
    }
    
    // Correlate events to find suspicious patterns
    result.correlations = correlator::correlate_events(&result.timeline_events);
    
    result
}

fn compare_parser_type(
    parser_type: &ParserType,
    before: &HashMap<ParserType, Value>,
    after: &HashMap<ParserType, Value>,
) -> Option<(ParserComparison, Vec<TimelineEvent>)> {
    let before_output = before.get(parser_type).cloned().unwrap_or(Value::Null);
    let after_output = after.get(parser_type).cloned().unwrap_or(Value::Null);
    
    // Perform comparison based on parser type
    let comparison = match parser_type {
        ParserType::Package => package_differ::compare_packages(&before_output, &after_output),
        ParserType::Process => process_differ::compare_processes(&before_output, &after_output),
        ParserType::Usb => usb_differ::compare_usb(&before_output, &after_output),
        ParserType::Power => power_differ::compare_power(&before_output, &after_output),
        _ => return None, // Skip unsupported parsers
    };
    
    // Extract timeline events from this comparison
    let events = match parser_type {
        ParserType::Package => package_differ::extract_timeline_events(&comparison),
        ParserType::Process => process_differ::extract_timeline_events(&comparison),
        ParserType::Usb => usb_differ::extract_timeline_events(&comparison),
        ParserType::Power => power_differ::extract_timeline_events(&comparison),
        _ => Vec::new(),
    };
    
    Some((comparison, events))
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parser_comparison_counts() {
        let mut comp = ParserComparison::new(ParserType::Package);
        comp.added.push(json!({"pkg": "test"}));
        comp.removed.push(json!({"pkg": "old"}));
        comp.modified.push((json!({"pkg": "app1", "v": "1.0"}), json!({"pkg": "app1", "v": "2.0"})));
        comp.unchanged_count = 5;
        
        assert_eq!(comp.total_changes(), 3);
        assert!(comp.has_changes());
    }

    #[test]
    fn test_comparison_result() {
        let mut result = ComparisonResult::new("before.txt".to_string(), "after.txt".to_string());
        
        let mut pkg_comp = ParserComparison::new(ParserType::Package);
        pkg_comp.added.push(json!({"pkg": "new"}));
        result.add_parser_comparison(pkg_comp);
        
        assert_eq!(result.total_changes(), 1);
        assert!(result.has_changes());
    }
}