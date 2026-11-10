//! Sensitive-data detection for the Riot agent.
//!
//! The rules are not reimplemented here: the extension's engine (`@tryriot/sonar-detection`,
//! bundled by `js/`) runs on an embedded QuickJS, so a paste is judged exactly as in the browser.
//! What the browser provided natively is provided by Rust instead: UTF-8 decoding and pdf text
//! extraction.
//!
//! ```no_run
//! use riot_detect::{Engine, EngineConfig, Options};
//! let engine = Engine::start(EngineConfig::default())?;
//! let out = engine.redact("IBAN FR76 3000 6000 0112 3456 7890 189", "com.openai.chat", &Options::default())?;
//! assert_eq!(out.text, "IBAN [IBAN_1]");
//! # Ok::<(), riot_detect::Error>(())
//! ```

mod engine;
mod pdf;
mod types;

pub use engine::{DETECTION_JS, Engine, EngineConfig, Error, FILE_MAX_BYTES, HeapStats, Result};
pub use types::{DetectOutcome, Detection, Detokenized, FileScan, Finding, Options, RedactOutcome, TypeCount};
