//! The Anthropic Messages API: which strings of a request are redacted, and how a response
//! (SSE or JSON) is detokenized. Pure: the caller passes the engine in as closures.
//!
//! Everything sent upstream is redacted, not only the user's turns: the client keeps the
//! detokenized answers and resends them as history, so assistant text and tool calls come back
//! holding the real values. Thinking blocks pass untouched both ways: they are signed, and the
//! API rejects a thinking block that differs from what it produced.
//!
//! The one exception is the client's own prompt at the head of `system`: up to the last block
//! cached with `scope: "global"`. That scope shares the cache across every API user, so the
//! client declares that text the same for everyone, not user data; and the API only accepts it
//! when what precedes it is unchanged (Claude Code's identity line, which the engine reads as
//! person names, made the request fail).

use std::collections::HashMap;

use serde_json::Value;

use super::tokens::{self, Escape, StreamDetokenizer};

/// The paths whose bodies are Messages API requests.
pub fn is_messages_path(path: &str) -> bool {
    matches!(path, "/v1/messages" | "/v1/messages/count_tokens")
}

/// Applies `redact` to every user-visible string of a Messages request, in place.
pub fn redact_request<E>(body: &mut Value, redact: &mut dyn FnMut(&str) -> Result<String, E>) -> Result<(), E> {
    let mut slots: Vec<&mut String> = vec![];
    let Value::Object(fields) = body else { return Ok(()) };
    for (key, value) in fields.iter_mut() {
        match (key.as_str(), value) {
            ("system", Value::Array(blocks)) => {
                let shared = blocks.iter().rposition(globally_cached).map_or(0, |i| i + 1);
                blocks[shared..].iter_mut().for_each(|b| block(b, &mut slots));
            }
            ("system", system) => content(system, &mut slots),
            ("messages", Value::Array(messages)) => {
                for message in messages {
                    if let Some(c) = message.get_mut("content") {
                        content(c, &mut slots);
                    }
                }
            }
            _ => {}
        }
    }
    for slot in slots {
        *slot = redact(slot)?;
    }
    Ok(())
}

fn globally_cached(block: &Value) -> bool {
    block.pointer("/cache_control/scope").and_then(Value::as_str) == Some("global")
}

/// A `content` field: a string, or an array of content blocks.
fn content<'a>(value: &'a mut Value, slots: &mut Vec<&'a mut String>) {
    match value {
        Value::String(s) => slots.push(s),
        Value::Array(blocks) => blocks.iter_mut().for_each(|b| block(b, slots)),
        _ => {}
    }
}

fn block<'a>(value: &'a mut Value, slots: &mut Vec<&'a mut String>) {
    let Value::Object(block) = value else { return };
    let kind = block.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
    match kind.as_str() {
        "text" => {
            if let Some(Value::String(s)) = block.get_mut("text") {
                slots.push(s);
            }
        }
        "tool_result" => {
            if let Some(c) = block.get_mut("content") {
                content(c, slots);
            }
        }
        "tool_use" | "server_tool_use" => {
            if let Some(input) = block.get_mut("input") {
                strings(input, slots);
            }
        }
        "document" => {
            for (key, value) in block.iter_mut() {
                match (key.as_str(), value) {
                    ("title" | "context", Value::String(s)) => slots.push(s),
                    ("source", Value::Object(source)) => {
                        let kind = source.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
                        match (kind.as_str(), source.get_mut(if kind == "text" { "data" } else { "content" })) {
                            ("text", Some(Value::String(s))) => slots.push(s),
                            ("content", Some(c)) => content(c, slots),
                            // base64 pdfs and images: not redacted here (see docs/network-interception.md).
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        // thinking, redacted_thinking (signed), image, search results, …
        _ => {}
    }
}

/// Every string in a JSON value (a tool call's input). Object keys are left alone.
fn strings<'a>(value: &'a mut Value, slots: &mut Vec<&'a mut String>) {
    match value {
        Value::String(s) => slots.push(s),
        Value::Array(items) => items.iter_mut().for_each(|v| strings(v, slots)),
        Value::Object(map) => map.values_mut().for_each(|v| strings(v, slots)),
        _ => {}
    }
}

/// Detokenizes a non-streamed Messages response (`stream: false`) in place.
pub fn detokenize_response(body: &mut Value, resolve: &mut dyn FnMut(&str) -> Option<String>) {
    let Some(Value::Array(blocks)) = body.get_mut("content") else { return };
    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(Value::String(s)) = b.get_mut("text") {
                    *s = tokens::replace(s, Escape::None, resolve);
                }
            }
            Some("tool_use") => {
                let mut slots = vec![];
                if let Some(input) = b.get_mut("input") {
                    strings(input, &mut slots);
                }
                for s in slots {
                    *s = tokens::replace(s, Escape::None, resolve);
                }
            }
            _ => {}
        }
    }
}

/// Rewrites a Messages SSE stream: `text_delta` and `input_json_delta` go through a
/// per-block stream detokenizer, whose held tail is flushed as one more delta before the
/// block's `content_block_stop`. Every other event passes byte for byte.
#[derive(Debug, Default)]
pub struct SseRewriter {
    buffer: Vec<u8>,
    blocks: HashMap<u64, StreamDetokenizer>,
}

impl SseRewriter {
    pub fn push(&mut self, chunk: &[u8], resolve: &mut dyn FnMut(&str) -> Option<String>) -> Vec<u8> {
        self.buffer.extend_from_slice(chunk);
        let mut out = vec![];
        while let Some(end) = event_end(&self.buffer) {
            let event: Vec<u8> = self.buffer.drain(..end).collect();
            self.event(&event, resolve, &mut out);
        }
        out
    }

    /// The upstream ended: whatever is left is passed on as it is.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    fn event(&mut self, raw: &[u8], resolve: &mut dyn FnMut(&str) -> Option<String>, out: &mut Vec<u8>) {
        let Some(mut data) = data_json(raw) else { return out.extend_from_slice(raw) };
        let index = data.get("index").and_then(Value::as_u64);
        match (data.get("type").and_then(Value::as_str), index) {
            (Some("content_block_start"), Some(index)) => {
                let escape = match data.pointer("/content_block/type").and_then(Value::as_str) {
                    Some("text") => Some(Escape::None),
                    Some("tool_use") => Some(Escape::JsonString),
                    _ => None,
                };
                if let Some(escape) = escape {
                    self.blocks.insert(index, StreamDetokenizer::new(escape));
                }
                out.extend_from_slice(raw);
            }
            (Some("content_block_delta"), Some(index)) => {
                let field = match data.pointer("/delta/type").and_then(Value::as_str) {
                    Some("text_delta") => "text",
                    Some("input_json_delta") => "partial_json",
                    _ => return out.extend_from_slice(raw),
                };
                let (Some(detok), Some(Value::String(text))) =
                    (self.blocks.get_mut(&index), data.get_mut("delta").and_then(|d| d.get_mut(field)))
                else {
                    return out.extend_from_slice(raw);
                };
                *text = detok.push(text, resolve);
                if !text.is_empty() {
                    write_event("content_block_delta", &data, out);
                }
            }
            (Some("content_block_stop"), Some(index)) => {
                if let Some(mut detok) = self.blocks.remove(&index) {
                    let held = detok.finish();
                    if !held.is_empty() {
                        let field = match detok.escape() {
                            Escape::JsonString => ("input_json_delta", "partial_json"),
                            Escape::None => ("text_delta", "text"),
                        };
                        let delta = serde_json::json!({
                            "type": "content_block_delta",
                            "index": index,
                            "delta": { "type": field.0, field.1: held },
                        });
                        write_event("content_block_delta", &delta, out);
                    }
                }
                out.extend_from_slice(raw);
            }
            _ => out.extend_from_slice(raw),
        }
    }
}

/// End (exclusive) of the first complete event: a blank line, `\n\n` or `\r\n\r\n`.
fn event_end(buffer: &[u8]) -> Option<usize> {
    let lf = buffer.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The event's `data:` payload, parsed, when it is one JSON object.
fn data_json(raw: &[u8]) -> Option<Value> {
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

fn write_event(name: &str, data: &Value, out: &mut Vec<u8>) {
    out.extend_from_slice(format!("event: {name}\ndata: {data}\n\n").as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tokenize(text: &str) -> Result<String, ()> {
        Ok(text.replace("jean.dupont@example.com", "[EMAIL_1]"))
    }

    fn known(token: &str) -> Option<String> {
        (token == "[EMAIL_1]").then(|| "jean.dupont@example.com".into())
    }

    #[test]
    fn redacts_every_text_sent_upstream_but_signed_thinking() {
        let mail = "jean.dupont@example.com";
        let mut body = json!({
            "model": "claude-haiku-5-5",
            "system": [{ "type": "text", "text": format!("User: {mail}"), "cache_control": { "type": "ephemeral" } }],
            "messages": [
                { "role": "user", "content": format!("Write to {mail}") },
                { "role": "assistant", "content": [
                    { "type": "thinking", "thinking": format!("They want {mail}"), "signature": "sig" },
                    { "type": "text", "text": format!("Sure, {mail}.") },
                    { "type": "tool_use", "id": "t1", "name": "Write", "input": { "content": format!("to: {mail}"), "lines": [mail] } }
                ]},
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": [{ "type": "text", "text": format!("wrote {mail}") }] },
                    { "type": "tool_result", "tool_use_id": "t2", "content": format!("cat: {mail}") },
                    { "type": "document", "source": { "type": "text", "media_type": "text/plain", "data": mail } },
                    { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "jean.dupont@example.com" } }
                ]}
            ]
        });
        redact_request(&mut body, &mut tokenize).unwrap();
        let out = body.to_string();
        assert_eq!(out.matches(mail).count(), 2, "only the thinking block and the image data keep it: {out}");
        assert_eq!(body["messages"][1]["content"][0]["thinking"], format!("They want {mail}"));
        assert_eq!(body["system"][0]["text"], "User: [EMAIL_1]");
        assert_eq!(body["messages"][1]["content"][2]["input"]["lines"][0], "[EMAIL_1]");
        assert_eq!(body["messages"][2]["content"][2]["source"]["data"], "[EMAIL_1]");
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn the_globally_cached_head_of_system_is_left_as_sent() {
        let mail = "jean.dupont@example.com";
        let global = json!({ "type": "ephemeral", "scope": "global" });
        let mut body = json!({
            "system": [
                { "type": "text", "text": "x-anthropic-billing-header: cc_version=1" },
                { "type": "text", "text": format!("You are a Claude agent ({mail} stands in for a false positive).") },
                { "type": "text", "text": "Static instructions.", "cache_control": global },
                { "type": "text", "text": format!("Environment: user {mail}"), "cache_control": { "type": "ephemeral" } }
            ],
            "messages": []
        });
        let sent = body.clone();
        redact_request(&mut body, &mut tokenize).unwrap();
        assert_eq!(body["system"].as_array().unwrap()[..3], sent["system"].as_array().unwrap()[..3], "the shared prefix is left as sent");
        assert_eq!(body["system"][3]["text"], "Environment: user [EMAIL_1]");
    }

    #[test]
    fn a_redaction_error_stops_the_request() {
        let mut body = json!({ "messages": [{ "role": "user", "content": "x" }] });
        assert!(redact_request(&mut body, &mut |_| Err::<String, _>("engine down")).is_err());
    }

    fn sse(events: &[Value]) -> String {
        events.iter().map(|e| format!("event: {}\ndata: {}\n\n", e["type"].as_str().unwrap(), e)).collect()
    }

    /// The text and tool input the client rebuilds from a stream, per block index.
    fn rebuild(stream: &str) -> (String, String) {
        let (mut text, mut json) = (String::new(), String::new());
        for event in stream.split("\n\n").filter(|e| !e.is_empty()) {
            let data: Value = serde_json::from_str(event.lines().find_map(|l| l.strip_prefix("data: ")).unwrap()).unwrap();
            match data.pointer("/delta/type").and_then(Value::as_str) {
                Some("text_delta") => text.push_str(data["delta"]["text"].as_str().unwrap()),
                Some("input_json_delta") => json.push_str(data["delta"]["partial_json"].as_str().unwrap()),
                _ => {}
            }
        }
        (text, json)
    }

    fn upstream() -> String {
        sse(&[
            json!({ "type": "message_start", "message": { "id": "m" } }),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "thinking", "thinking": "" } }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "thinking_delta", "thinking": "mail [EMAIL_1]" } }),
            json!({ "type": "content_block_stop", "index": 0 }),
            json!({ "type": "content_block_start", "index": 1, "content_block": { "type": "text", "text": "" } }),
            json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "text_delta", "text": "OK [EMA" } }),
            json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "text_delta", "text": "IL_1] and [" } }),
            json!({ "type": "content_block_stop", "index": 1 }),
            json!({ "type": "content_block_start", "index": 2, "content_block": { "type": "tool_use", "id": "t", "name": "Write", "input": {} } }),
            json!({ "type": "content_block_delta", "index": 2, "delta": { "type": "input_json_delta", "partial_json": "{\"to\": \"[EMAIL" } }),
            json!({ "type": "content_block_delta", "index": 2, "delta": { "type": "input_json_delta", "partial_json": "_1]\"}" } }),
            json!({ "type": "content_block_stop", "index": 2 }),
            json!({ "type": "message_stop" }),
        ])
    }

    #[test]
    fn detokenizes_text_and_tool_input_across_chunk_boundaries() {
        let stream = upstream();
        // Every split of the byte stream into two network reads gives the same result.
        for cut in [1, 37, stream.len() / 2, stream.len() - 3] {
            let mut rw = SseRewriter::default();
            let mut out = rw.push(&stream.as_bytes()[..cut], &mut known);
            out.extend(rw.push(&stream.as_bytes()[cut..], &mut known));
            out.extend(rw.finish());
            let out = String::from_utf8(out).unwrap();
            let (text, json) = rebuild(&out);
            assert_eq!(text, "OK jean.dupont@example.com and [");
            assert_eq!(serde_json::from_str::<Value>(&json).unwrap()["to"], "jean.dupont@example.com");
            assert!(out.contains(r#""thinking":"mail [EMAIL_1]""#), "thinking is signed: left as is");
            assert!(out.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
        }
    }

    #[test]
    fn detokenizes_a_json_response() {
        let mut body = json!({ "content": [
            { "type": "text", "text": "OK [EMAIL_1]" },
            { "type": "tool_use", "id": "t", "name": "Write", "input": { "to": "[EMAIL_1]" } },
            { "type": "thinking", "thinking": "[EMAIL_1]", "signature": "s" }
        ]});
        detokenize_response(&mut body, &mut known);
        assert_eq!(body["content"][0]["text"], "OK jean.dupont@example.com");
        assert_eq!(body["content"][1]["input"]["to"], "jean.dupont@example.com");
        assert_eq!(body["content"][2]["thinking"], "[EMAIL_1]");
    }
}
