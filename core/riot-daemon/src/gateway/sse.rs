//! Server-sent events framing, shared by the API adapters.

use serde_json::Value;

/// Rewrites an SSE body chunk by chunk; what `push` returns is final.
pub trait Rewrite: Send {
    fn push(&mut self, chunk: &[u8], resolve: &mut dyn FnMut(&str) -> Option<String>) -> Vec<u8>;
    /// The upstream ended.
    fn finish(&mut self) -> Vec<u8>;
}

/// End (exclusive) of the first complete event: a blank line, `\n\n` or `\r\n\r\n`.
pub fn event_end(buffer: &[u8]) -> Option<usize> {
    let lf = buffer.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The event's `data:` payload, parsed, when it is one JSON object.
pub fn data_json(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    let data: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(|d| d.strip_prefix(' ').unwrap_or(d))
        .collect();
    if data.is_empty() {
        return None;
    }
    serde_json::from_str(&data.join("\n")).ok().filter(Value::is_object)
}

pub fn write_event(name: &str, data: &Value, out: &mut Vec<u8>) {
    out.extend_from_slice(format!("event: {name}\ndata: {data}\n\n").as_bytes());
}
