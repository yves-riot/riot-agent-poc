//! Result shapes, mirroring what `js/src/host.ts` serialises. Indexes are the engine's: UTF-16
//! code-unit offsets into the input string, as in the extension.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Detection categories (`secrets`, `financial_data`, `personal_data`) and per-call limits.
/// Absent categories are enabled, as in the extension (`categoryEnablement()`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<BTreeMap<String, bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Detection {
    pub flag: String,
    pub category: String,
    pub severity: String,
    pub name: String,
    pub label: String,
    pub value: String,
    pub index: usize,
}

/// Distinct detected values per type: the unit parrot's reports count in (`detectionCounts`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeCount {
    #[serde(rename = "type")]
    pub kind: String,
    pub count: u32,
}

/// One minted numbered token, without its value (values never leave the JS heap through here).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub flag: String,
    pub label: String,
    pub name: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactOutcome {
    /// The input with each detection replaced by its numbered token (`[IBAN_1]`).
    pub text: String,
    pub oversized: bool,
    pub detections: Vec<Detection>,
    pub findings: Vec<Finding>,
    pub counts: Vec<TypeCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectOutcome {
    pub detections: Vec<Detection>,
    pub oversized: bool,
    /// Detector ids that threw; non-empty means the scan was partial.
    pub failed: Vec<String>,
    pub counts: Vec<TypeCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Detokenized {
    pub text: String,
    pub replaced: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum FileScan {
    Scanned { format: String, detections: Vec<Detection>, counts: Vec<TypeCount> },
    Unsupported {
        #[serde(rename = "type")]
        kind: String,
    },
    Oversized { bytes: u64 },
    /// Extraction or detection failed. Callers must treat it as "not clean" (fail closed).
    Error { stage: String, error: String },
}

impl FileScan {
    /// True when the file may be delivered: scanned and nothing found.
    pub fn is_clean(&self) -> bool {
        matches!(self, FileScan::Scanned { detections, .. } if detections.is_empty())
    }
}
