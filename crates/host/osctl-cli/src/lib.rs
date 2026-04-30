//! CLI shell for read-only Semantic Virtual ISA views.
//!
//! Argument parsing, file loading, and output selection live here. Stable view
//! rendering belongs in `osctl-view`.

mod cli;

pub use cli::run;
