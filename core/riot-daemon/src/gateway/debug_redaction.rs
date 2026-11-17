//! Development builds only (`--features debug-redaction`): logs the values the gateway redacts
//! and restores, to check against what an API actually receives. A build without the feature
//! has none of this code: production binaries cannot log a value, whatever their settings.
//!
//! Each token in a text as sent is logged with the value it stands for, and any detected
//! value still present in that text is logged as an error: what left in clear.

use riot_detect::{Engine, RedactOutcome};

use super::tokens;

const TARGET: &str = "riot_daemon::debug_redaction";

pub fn warn_enabled() {
    tracing::warn!(target: TARGET, "debug-redaction build: redacted and restored values are logged");
}

/// A text as it is sent upstream, after redaction.
pub fn sent(engine: &Engine, scope: &str, out: &RedactOutcome) {
    if out.detections.is_empty() {
        return;
    }
    for range in tokens::find(&out.text) {
        let token = &out.text[range];
        let value = engine.detokenize(token, scope).ok().filter(|d| d.replaced > 0).map(|d| d.text);
        tracing::warn!(target: TARGET, token, value = value.as_deref().unwrap_or("<not a token of this scope>"), "sent");
    }
    for detection in &out.detections {
        if out.text.contains(&detection.value) {
            tracing::error!(target: TARGET, label = %detection.label, value = %detection.value, "sent in clear");
        }
    }
}

/// A token of a response, as given back to the app.
pub fn restored(token: &str, value: Option<&str>) {
    tracing::warn!(target: TARGET, token, value = value.unwrap_or("<left as is>"), "restored");
}
