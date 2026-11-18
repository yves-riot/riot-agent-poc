//! Development builds only (`--features debug-redaction`): logs the values the gateway redacts
//! and restores, to check against what an API actually receives. A build without the feature
//! has none of this code: production binaries cannot log a value, whatever their settings.
//!
//! Each token in a text as sent is logged with the value it stands for, and any detected
//! value still present in that text is logged as an error: what left in clear. Requests and
//! WebSocket messages to a policy host that no adapter reads (telemetry, other endpoints) go
//! through the detector too: a value found in one is logged, to find what else carries a prompt.

use bytes::Bytes;
use hyper::header::HeaderValue;
use riot_detect::{Engine, Options, RedactOutcome};

use super::{tokens, websocket};

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

/// A request body to a policy host, passed on as it is.
pub fn forwarded_body(engine: &Engine, options: &Options, host: &str, path: &str, encoding: Option<HeaderValue>, body: Bytes) {
    if body.is_empty() {
        return;
    }
    match super::decoded(encoding, body) {
        Ok(body) => forwarded(engine, options, host, path, &String::from_utf8_lossy(&body)),
        Err(e) => tracing::warn!(target: TARGET, host, path, error = ?e, "forwarded unchecked"),
    }
}

/// The client's messages on a WebSocket to a policy host that no adapter reads, checked as
/// they pass.
pub fn watched_up(engine: Engine, options: Options, host: &str, path: &str) -> websocket::UpHook {
    let (host, path) = (host.to_owned(), path.to_owned());
    Box::new(move |text| {
        forwarded(&engine, &options, &host, &path, text);
        Ok(text.to_owned())
    })
}

fn forwarded(engine: &Engine, options: &Options, host: &str, path: &str, text: &str) {
    // The engine call blocks on the JS thread.
    match tokio::task::block_in_place(|| engine.detect(text, options)) {
        Ok(outcome) => {
            if outcome.oversized {
                tracing::warn!(target: TARGET, host, path, bytes = text.len(), "forwarded, too large to check whole");
            }
            for detection in outcome.detections {
                tracing::error!(target: TARGET, host, path, label = %detection.label, value = %detection.value, "forwarded with a detected value");
            }
        }
        Err(e) => tracing::warn!(target: TARGET, host, path, error = %e, "forwarded unchecked"),
    }
}
