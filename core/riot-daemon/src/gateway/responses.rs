//! The OpenAI Responses API as Codex and ChatGPT use it (`chatgpt.com/backend-api/codex/responses`,
//! over a WebSocket or SSE): which strings of a `response.create` are redacted, and how its
//! event stream is detokenized. Pure, like `anthropic`.
//!
//! Requests are walked generically, so that item types the client adds later are redacted too:
//! every string of `instructions` and `input` is text, except under keys that hold identifiers
//! or opaque data (`OPAQUE`). With `previous_response_id`, Codex sends only the new items; the
//! rest of the conversation stays on the server, which only ever saw tokens.
//!
//! Events are detokenized generically too: every `*.delta` stream through a detokenizer of its
//! own (keyed by item and part), any other event has its tokens replaced in every string. The
//! full text comes back several times (`output_text.done`, `content_part.done`,
//! `output_item.done`, `response.completed`): each one is rewritten.

use std::collections::HashMap;

use serde_json::Value;

use super::sse::{Rewrite, data_json, event_end, write_event};
use super::tokens::{self, Escape, StreamDetokenizer};

/// Keys whose strings are identifiers, enums or opaque data: never redacted nor detokenized.
const OPAQUE: &[&str] = &[
    "type",
    "id",
    "call_id",
    "item_id",
    "response_id",
    "role",
    "status",
    "name",
    "phase",
    "encrypted_content",
    "internal_chat_message_metadata_passthrough",
    "image_url",
    "file_id",
    "file_data",
    "obfuscation",
];
/// Input items that hold tool definitions, not conversation.
const DEFINITIONS: &[&str] = &["additional_tools"];

pub fn is_responses_path(path: &str) -> bool {
    path.ends_with("/responses")
}

/// A string to redact: plain text, or a function call's `arguments` (JSON in a string).
enum Slot<'a> {
    Text(&'a mut String),
    Arguments(&'a mut String),
}

/// Applies `redact` to every text of a `response.create` (a WebSocket message or an HTTP
/// body), in place.
pub fn redact_request<E>(body: &mut Value, redact: &mut dyn FnMut(&str) -> Result<String, E>) -> Result<(), E> {
    let mut slots = vec![];
    let Value::Object(fields) = body else { return Ok(()) };
    for (key, value) in fields.iter_mut() {
        match (key.as_str(), value) {
            ("instructions", Value::String(s)) => slots.push(Slot::Text(s)),
            ("input", Value::String(s)) => slots.push(Slot::Text(s)),
            ("input", Value::Array(items)) => {
                for item in items {
                    let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
                    if !DEFINITIONS.contains(&kind) {
                        walk(item, None, &mut slots);
                    }
                }
            }
            _ => {}
        }
    }
    for slot in slots {
        match slot {
            Slot::Text(s) => *s = redact(s)?,
            Slot::Arguments(s) => *s = redact_arguments(s, redact)?,
        }
    }
    Ok(())
}

fn walk<'a>(value: &'a mut Value, key: Option<&str>, slots: &mut Vec<Slot<'a>>) {
    match value {
        Value::String(s) => match key {
            Some(k) if OPAQUE.contains(&k) => {}
            Some("arguments") => slots.push(Slot::Arguments(s)),
            _ => slots.push(Slot::Text(s)),
        },
        // An array's strings keep the array's key (`"command": ["echo", "…"]`).
        Value::Array(values) => values.iter_mut().for_each(|v| walk(v, key, slots)),
        Value::Object(fields) => fields.iter_mut().for_each(|(k, v)| walk(v, Some(k), slots)),
        _ => {}
    }
}

/// A function call's arguments: each string inside the JSON is redacted, so a value is never
/// cut by JSON escapes; re-serialized only when something changed.
fn redact_arguments<E>(arguments: &str, redact: &mut dyn FnMut(&str) -> Result<String, E>) -> Result<String, E> {
    let Ok(mut json) = serde_json::from_str::<Value>(arguments) else { return redact(arguments) };
    let mut strings = vec![];
    collect_strings(&mut json, &mut strings);
    let mut changed = false;
    for s in strings {
        let out = redact(s)?;
        changed |= out != *s;
        *s = out;
    }
    Ok(if changed { json.to_string() } else { arguments.to_owned() })
}

fn collect_strings<'a>(value: &'a mut Value, out: &mut Vec<&'a mut String>) {
    match value {
        Value::String(s) => out.push(s),
        Value::Array(values) => values.iter_mut().for_each(|v| collect_strings(v, out)),
        Value::Object(fields) => fields.values_mut().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// Replaces the tokens in every string of a complete JSON value (an event, a response).
pub fn detokenize_value(value: &mut Value, resolve: &mut dyn FnMut(&str) -> Option<String>) {
    replace_in(value, None, resolve);
}

fn replace_in(value: &mut Value, key: Option<&str>, resolve: &mut dyn FnMut(&str) -> Option<String>) {
    match value {
        Value::String(s) => match key {
            Some(k) if OPAQUE.contains(&k) => {}
            // Function call arguments are JSON: a value goes inside one of its string literals.
            Some("arguments") => *s = tokens::replace(s, Escape::JsonString, resolve),
            _ => *s = tokens::replace(s, Escape::None, resolve),
        },
        Value::Array(values) => values.iter_mut().for_each(|v| replace_in(v, key, resolve)),
        Value::Object(fields) => fields.iter_mut().for_each(|(k, v)| replace_in(v, Some(k), resolve)),
        _ => {}
    }
}

/// One `*.delta` stream: its detokenizer, and its last event, to flush what it holds back.
struct Stream {
    detok: StreamDetokenizer,
    last: Value,
}

/// Detokenizes the Responses event stream, event by event.
#[derive(Default)]
pub struct EventRewriter {
    /// Keyed by delta type, item and part index.
    streams: HashMap<(String, String, u64), Stream>,
}

impl EventRewriter {
    /// The events to send in place of `event`: usually one, preceded by flushed deltas when
    /// `event` ends a stream that held back a possible token.
    pub fn event(&mut self, mut event: Value, resolve: &mut dyn FnMut(&str) -> Option<String>) -> Vec<Value> {
        let kind = event.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
        let item = event.get("item_id").and_then(Value::as_str).map(str::to_owned);
        if kind.ends_with(".delta")
            && let (Some(item), Some(Value::String(delta))) = (&item, event.get("delta"))
        {
            let index = ["content_index", "summary_index"].iter().find_map(|k| event.get(*k).and_then(Value::as_u64)).unwrap_or(0);
            // Function call arguments are JSON; custom tool input (`exec` code, patches) is
            // raw text.
            let escape = if kind.contains("function_call_arguments") { Escape::JsonString } else { Escape::None };
            let stream = self
                .streams
                .entry((kind, item.clone(), index))
                .or_insert_with(|| Stream { detok: StreamDetokenizer::new(escape), last: Value::Null });
            let out = stream.detok.push(delta, resolve);
            event["delta"] = Value::String(out);
            stream.last = event.clone();
            // Sent even when empty: a held-back prefix must not leave a gap in the sequence.
            return vec![event];
        }

        // Any other event closes the streams of its item; a response's end closes them all.
        let ends_response = matches!(kind.as_str(), "response.completed" | "response.failed" | "response.incomplete" | "error");
        let item = item.or_else(|| event.pointer("/item/id").and_then(Value::as_str).map(str::to_owned));
        let mut out = vec![];
        let closed: Vec<_> = self.streams.keys().filter(|(_, i, _)| ends_response || Some(i) == item.as_ref()).cloned().collect();
        for key in closed {
            let Some(mut stream) = self.streams.remove(&key) else { continue };
            let held = stream.detok.finish();
            if !held.is_empty() {
                stream.last["delta"] = Value::String(held);
                out.push(stream.last);
            }
        }
        detokenize_value(&mut event, resolve);
        out.push(event);
        out
    }
}

/// The same events over SSE (`POST …/responses` with `stream: true`).
#[derive(Default)]
pub struct SseRewriter {
    buffer: Vec<u8>,
    events: EventRewriter,
}

impl Rewrite for SseRewriter {
    fn push(&mut self, chunk: &[u8], resolve: &mut dyn FnMut(&str) -> Option<String>) -> Vec<u8> {
        self.buffer.extend_from_slice(chunk);
        let mut out = vec![];
        while let Some(end) = event_end(&self.buffer) {
            let raw: Vec<u8> = self.buffer.drain(..end).collect();
            match data_json(&raw) {
                Some(event) => {
                    for event in self.events.event(event, resolve) {
                        let name = event.get("type").and_then(Value::as_str).unwrap_or("message").to_owned();
                        write_event(&name, &event, &mut out);
                    }
                }
                None => out.extend_from_slice(&raw),
            }
        }
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MAIL: &str = "jean.dupont@example.com";

    fn tokenize(text: &str) -> Result<String, ()> {
        Ok(text.replace(MAIL, "[EMAIL_1]"))
    }

    fn known(token: &str) -> Option<String> {
        (token == "[EMAIL_1]").then(|| MAIL.into())
    }

    /// A `response.create` as Codex sends it (shape captured from Codex 0.167.0).
    #[test]
    fn redacts_every_text_of_the_input_but_identifiers_and_definitions() {
        let mut body = json!({
            "type": "response.create",
            "model": "gpt-6",
            "previous_response_id": "resp_1",
            "prompt_cache_key": "k",
            "input": [
                { "type": "additional_tools", "id": "at_1", "role": "developer", "tools": [{ "name": "t", "description": MAIL }] },
                { "type": "message", "id": "m_1", "role": "user", "internal_chat_message_metadata_passthrough": MAIL,
                  "content": [{ "type": "input_text", "text": format!("Mail {MAIL}") }, { "type": "input_image", "image_url": MAIL }] },
                { "type": "custom_tool_call", "call_id": "c_1", "name": "exec", "input": format!("tools.exec_command({{cmd:\"echo {MAIL}\"}})") },
                { "type": "custom_tool_call_output", "call_id": "c_1", "output": format!("{MAIL}\n") },
                { "type": "function_call", "call_id": "c_2", "name": "shell", "arguments": format!("{{\"command\":[\"echo\",\"{MAIL}\"]}}") },
                { "type": "function_call", "call_id": "c_3", "name": "noop", "arguments": "{ \"a\" : 1 }" },
                { "type": "function_call_output", "call_id": "c_2", "output": MAIL },
                { "type": "local_shell_call", "action": { "command": ["echo", MAIL] } },
                { "type": "reasoning", "encrypted_content": MAIL, "summary": [{ "type": "summary_text", "text": MAIL }] }
            ]
        });
        redact_request(&mut body, &mut tokenize).unwrap();
        let input = &body["input"];
        assert_eq!(input[0]["tools"][0]["description"], MAIL, "tool definitions are left alone");
        assert_eq!(input[1]["content"][0]["text"], "Mail [EMAIL_1]");
        assert_eq!(input[1]["content"][1]["image_url"], MAIL);
        assert_eq!(input[1]["internal_chat_message_metadata_passthrough"], MAIL);
        assert_eq!(input[2]["input"], "tools.exec_command({cmd:\"echo [EMAIL_1]\"})");
        assert_eq!(input[3]["output"], "[EMAIL_1]\n");
        assert_eq!(input[4]["arguments"], r#"{"command":["echo","[EMAIL_1]"]}"#);
        assert_eq!(input[5]["arguments"], "{ \"a\" : 1 }", "unchanged arguments keep their bytes");
        assert_eq!(input[6]["output"], "[EMAIL_1]");
        assert_eq!(input[7]["action"]["command"][1], "[EMAIL_1]");
        assert_eq!(input[8]["encrypted_content"], MAIL);
        assert_eq!(input[8]["summary"][0]["text"], "[EMAIL_1]");
        assert_eq!(body["previous_response_id"], "resp_1");
    }

    fn delta(kind: &str, item: &str, text: &str) -> Value {
        json!({ "type": kind, "item_id": item, "output_index": 0, "content_index": 0, "delta": text, "sequence_number": 1 })
    }

    fn run(events: Vec<Value>) -> Vec<Value> {
        let mut rewriter = EventRewriter::default();
        events.into_iter().flat_map(|e| rewriter.event(e, &mut known)).collect()
    }

    fn deltas(events: &[Value], kind: &str) -> String {
        events.iter().filter(|e| e["type"] == kind).map(|e| e["delta"].as_str().unwrap()).collect()
    }

    #[test]
    fn detokenizes_text_and_tool_input_across_events() {
        let out = run(vec![
            delta("response.output_text.delta", "m", "OK [EMA"),
            delta("response.output_text.delta", "m", "IL_1] et [EMAIL"),
            json!({ "type": "response.output_text.done", "item_id": "m", "content_index": 0, "text": "OK [EMAIL_1] et [EMAIL" }),
            json!({ "type": "response.output_item.done", "item": { "id": "m", "type": "message", "content": [{ "type": "output_text", "text": "OK [EMAIL_1]" }] } }),
            delta("response.custom_tool_call_input.delta", "c", "echo [EMAIL_"),
            delta("response.custom_tool_call_input.delta", "c", "1]"),
            delta("response.function_call_arguments.delta", "f", "{\"to\":\"[EMAIL_1]\"}"),
            json!({ "type": "response.completed", "response": { "output": [
                { "type": "function_call", "id": "f", "arguments": "{\"to\":\"[EMAIL_1]\"}" },
                { "type": "message", "id": "m", "content": [{ "type": "output_text", "text": "[EMAIL_1]" }] }
            ] } }),
        ]);
        assert_eq!(deltas(&out, "response.output_text.delta"), format!("OK {MAIL} et [EMAIL"), "the held tail is flushed before .done");
        assert!(out.iter().position(|e| e["type"] == "response.output_text.done") > out.iter().rposition(|e| e["type"] == "response.output_text.delta"));
        assert_eq!(out.iter().find(|e| e["type"] == "response.output_text.done").unwrap()["text"], format!("OK {MAIL} et [EMAIL"));
        assert_eq!(out.iter().find(|e| e["type"] == "response.output_item.done").unwrap()["item"]["content"][0]["text"], format!("OK {MAIL}"));
        assert_eq!(deltas(&out, "response.custom_tool_call_input.delta"), format!("echo {MAIL}"));
        assert_eq!(deltas(&out, "response.function_call_arguments.delta"), format!("{{\"to\":\"{MAIL}\"}}"));
        let completed = out.last().unwrap();
        assert_eq!(completed["response"]["output"][0]["arguments"], format!("{{\"to\":\"{MAIL}\"}}"));
        assert_eq!(completed["response"]["output"][1]["content"][0]["text"], MAIL);
    }

    #[test]
    fn identifiers_and_opaque_fields_are_not_detokenized() {
        let out = run(vec![json!({ "type": "x", "item_id": "[EMAIL_1]", "obfuscation": "[EMAIL_1]", "text": "[EMAIL_1]" })]);
        assert_eq!(out[0]["item_id"], "[EMAIL_1]");
        assert_eq!(out[0]["obfuscation"], "[EMAIL_1]");
        assert_eq!(out[0]["text"], MAIL);
    }

    #[test]
    fn sse_events_are_rewritten_whole() {
        let mut sse = SseRewriter::default();
        let body = [delta("response.output_text.delta", "m", "a [EMAIL_1"), delta("response.output_text.delta", "m", "] b")]
            .iter()
            .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
            .collect::<String>();
        let (a, b) = body.split_at(body.len() / 2);
        let mut out = sse.push(a.as_bytes(), &mut known);
        out.extend(sse.push(b.as_bytes(), &mut known));
        out.extend(sse.finish());
        let text: String = String::from_utf8(out)
            .unwrap()
            .split("\n\n")
            .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")))
            .map(|d| serde_json::from_str::<Value>(d).unwrap()["delta"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(text, format!("a {MAIL} b"));
    }
}
