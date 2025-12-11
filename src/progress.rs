use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

/// Progress tracker for parsing and analysis operations
pub struct ProgressTracker {
    multi: MultiProgress,
    enabled: bool,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(enabled: bool) -> Self {
        Self {
            multi: MultiProgress::new(),
            enabled,
        }
    }

    /// Create a progress bar for file reading
    pub fn create_file_progress(&self, file_size: u64) -> Option<ProgressBar> {
        if !self.enabled {
            return None;
        }

        let pb = self.multi.add(ProgressBar::new(file_size));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message("📂 Loading file...");
        Some(pb)
    }

    /// Create a progress bar for parser execution
    pub fn create_parser_progress(&self, parser_name: &str) -> Option<ProgressBar> {
        if !self.enabled {
            return None;
        }

        let pb = self.multi.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_message(format!("🔍 Parsing with {} parser...", parser_name));
        Some(pb)
    }

    /// Create a progress bar for multiple parsers
    pub fn create_multi_parser_progress(&self, total_parsers: usize) -> Option<ProgressBar> {
        if !self.enabled {
            return None;
        }

        let pb = self.multi.add(ProgressBar::new(total_parsers as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} parsers")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message("📊 Running parsers concurrently...");
        Some(pb)
    }

    /// Create a progress bar for Sigma rule loading
    pub fn create_rule_loading_progress(&self) -> Option<ProgressBar> {
        if !self.enabled {
            return None;
        }

        let pb = self.multi.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.blue} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_message("📜 Loading Sigma rules...");
        Some(pb)
    }

    /// Create a progress bar for Sigma evaluation
    pub fn create_sigma_progress(&self, total_entries: usize) -> Option<ProgressBar> {
        if !self.enabled {
            return None;
        }

        let pb = self.multi.add(ProgressBar::new(total_entries as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.yellow} [{elapsed_precise}] [{wide_bar:.yellow/blue}] {pos}/{len} entries ({per_sec}, {eta})")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb.set_message("🔎 Evaluating Sigma rules...");
        Some(pb)
    }

    /// Create a progress bar for per-parser Sigma evaluation
    pub fn create_parser_sigma_progress(&self, parser_name: &str, total_entries: usize) -> Option<ProgressBar> {
        if !self.enabled {
            return None;
        }

        let pb = self.multi.add(ProgressBar::new(total_entries as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.yellow} [{elapsed_precise}] [{wide_bar:.yellow/blue}] {pos}/{len} entries")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb.set_message(format!("  ↳ {} parser", parser_name));
        Some(pb)
    }

    /// Finish a progress bar with success message
    pub fn finish_with_message(pb: Option<ProgressBar>, message: &str) {
        if let Some(pb) = pb {
            pb.finish_with_message(message.to_string());
        }
    }

    /// Finish a progress bar and clear it
    pub fn finish_and_clear(pb: Option<ProgressBar>) {
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
    }

    /// Update progress bar position
    pub fn set_position(pb: &Option<ProgressBar>, pos: u64) {
        if let Some(pb) = pb {
            pb.set_position(pos);
        }
    }

    /// Increment progress bar
    pub fn inc(pb: &Option<ProgressBar>, delta: u64) {
        if let Some(pb) = pb {
            pb.inc(delta);
        }
    }

    /// Update progress bar message
    pub fn set_message(pb: &Option<ProgressBar>, message: &str) {
        if let Some(pb) = pb {
            pb.set_message(message.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_tracker_disabled() {
        let tracker = ProgressTracker::new(false);
        let pb = tracker.create_file_progress(1000);
        assert!(pb.is_none());
    }

    #[test]
    fn test_progress_tracker_enabled() {
        let tracker = ProgressTracker::new(true);
        let pb = tracker.create_file_progress(1000);
        assert!(pb.is_some());
        ProgressTracker::finish_and_clear(pb);
    }
}