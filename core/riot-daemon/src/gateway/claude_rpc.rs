//! Claude Desktop's conversations: Connect RPC over protobuf, at
//! `claude.ai/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/<Method>` (and
//! `/v1/code/rpc/…` for Claude Code sessions). Unary calls are `application/proto`, streams
//! `application/connect+proto`. Pure, like `anthropic` and `responses`.
//!
//! A message leaves in `PerformAction`, its text in field 2.3 (the send action), and is
//! redacted there, with the text of each file attached inline (an `InlineAttachment` in field
//! 2.15: a `.txt`, its content in field 4). The schema is not published: the paths come from
//! the app's own requests.
//!
//! Answers come back in `StreamTimeline`: the conversation's title, the user's message as the
//! server keeps it, and the assistant's text in two forms. A block snapshot (`1.1.5`, a
//! `ContentBlock`) holds its whole text so far; a delta (`1.2`: the block's id, then text to
//! append in field 2, thinking in field 6) only the next piece, which can end inside a token.
//! Deltas go through a stream detokenizer per block, which holds a token's start back until
//! the next delta; every other string of every response is detokenized where it is, the
//! timeline's shape changing with the features the app shows. A snapshot drops what its block
//! held back: it carries the text whole.
//!
//! An attached file comes back from `GET /api/organizations/<org>/files/<id>/contents` (the
//! app's preview): text files are detokenized like the timeline.
//!
//! The app signs each event it sends with its device key, over a hash of the event's content.
//! Redacting the text changes that content: the server then asks the app to sign what it
//! received (`WorkspaceDeviceSignatureAsk` in the timeline), and the app does, in a second
//! `PerformAction`. Nothing here touches a signature.

use std::collections::HashMap;

use super::protobuf::{self, Malformed};
use super::tokens::{self, Escape, StreamDetokenizer};

const SERVICE: &str = "/anthropic.bard.api.v1alpha.ConversationService/";

/// Strings of `PerformAction` that carry the user's text.
const SENT_TEXT: &[&[u64]] = &[
    // The send action's text.
    &[2, 3],
    // Each inline attachment's text (`InlineAttachment.extracted_content`).
    &[2, 15, 4],
];

/// The method a path calls on the conversation service, if it does.
pub fn method(path: &str) -> Option<&str> {
    let (_, method) = path.split_once(SERVICE)?;
    (!method.is_empty() && !method.contains('/')).then_some(method)
}

/// Whether a path downloads an uploaded or attached file's content.
pub fn is_file_contents(path: &str) -> bool {
    path.strip_prefix("/api/organizations/").is_some_and(|rest| {
        let parts: Vec<&str> = rest.split('/').collect();
        matches!(parts.as_slice(), [_, "files", _, "contents"])
    })
}

/// Detokenizes a text file. `None` when nothing changed.
pub fn detokenize_text(text: &str, resolve: &mut dyn FnMut(&str) -> Option<String>) -> Option<String> {
    let out = tokens::replace(text, Escape::None, resolve);
    (out != text).then_some(out)
}

/// Whether a method's request carries the user's text.
pub fn sends_text(method: &str) -> bool {
    method == "PerformAction"
}

/// Redacts a `PerformAction` request. `None` when nothing changed.
pub fn redact_request<E: From<Malformed>>(body: &[u8], redact: &mut dyn FnMut(&str) -> Result<String, E>) -> Result<Option<Vec<u8>>, E> {
    let mut current: Option<Vec<u8>> = None;
    for path in SENT_TEXT {
        let message = current.as_deref().unwrap_or(body);
        let rewritten = protobuf::rewrite_at(message, path, &mut |text: &str| -> Result<Option<String>, E> {
            let out = redact(text)?;
            Ok((out != text).then_some(out))
        })?;
        if rewritten.is_some() {
            current = rewritten;
        }
    }
    Ok(current)
}

/// A delta's appended strings: text and thinking.
const DELTA_TEXTS: &[u64] = &[2, 6];

/// Detokenizes a `StreamTimeline` stream, message after message.
#[derive(Default)]
pub struct TimelineDetokenizer {
    /// By block id and delta field.
    deltas: HashMap<(String, u64), StreamDetokenizer>,
}

impl TimelineDetokenizer {
    /// One message of the stream. `None` when nothing changed.
    pub fn message(&mut self, message: &[u8], resolve: &mut dyn FnMut(&str) -> Option<String>) -> Option<Vec<u8>> {
        let mut current: Option<Vec<u8>> = None;
        if let Some(block) = protobuf::string_at(message, &[1, 2, 1]).map(str::to_owned) {
            for &field in DELTA_TEXTS {
                let detokenizer = self.deltas.entry((block.clone(), field)).or_insert_with(|| StreamDetokenizer::new(Escape::None));
                let rewritten = protobuf::rewrite_at::<Malformed>(current.as_deref().unwrap_or(message), &[1, 2, field], &mut |text| {
                    let out = detokenizer.push(text, resolve);
                    Ok((out != text).then_some(out))
                });
                if let Ok(Some(out)) = rewritten {
                    current = Some(out);
                }
            }
        }
        if let Some(block) = protobuf::string_at(message, &[1, 1, 5, 1]) {
            self.deltas.retain(|(id, _), _| id != block);
        }
        detokenize_message(current.as_deref().unwrap_or(message), resolve).or(current)
    }
}

/// Detokenizes every string of a response message. `None` when nothing changed.
pub fn detokenize_message(message: &[u8], resolve: &mut dyn FnMut(&str) -> Option<String>) -> Option<Vec<u8>> {
    protobuf::rewrite_strings(message, &mut |text| {
        if tokens::find(text).is_empty() {
            return None;
        }
        let out = tokens::replace(text, Escape::None, resolve);
        (out != text).then_some(out)
    })
}

#[cfg(test)]
mod tests {
    use super::super::protobuf::tests::{len_field, varint_field};
    use super::*;

    fn redact(text: &str) -> Result<String, Malformed> {
        Ok(text.replace("jean.dupont@acme.fr", "[EMAIL_1]"))
    }

    fn resolve(token: &str) -> Option<String> {
        (token == "[EMAIL_1]").then(|| "jean.dupont@acme.fr".to_owned())
    }

    #[test]
    fn methods_are_read_from_both_routes() {
        assert_eq!(method("/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction"), Some("PerformAction"));
        assert_eq!(method("/v1/code/rpc/anthropic.bard.api.v1alpha.ConversationService/StreamTimeline"), Some("StreamTimeline"));
        assert_eq!(method("/api/organizations/x/chat_conversations"), None);
        assert_eq!(method("/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/"), None);
    }

    #[test]
    fn file_contents_paths_are_recognised() {
        assert!(is_file_contents("/api/organizations/org-1/files/file-1/contents"));
        assert!(!is_file_contents("/api/organizations/org-1/files/file-1"));
        assert!(!is_file_contents("/api/organizations/org-1/projects/p/files/file-1/contents"));
        assert_eq!(detokenize_text("Email : [EMAIL_1]", &mut resolve).as_deref(), Some("Email : jean.dupont@acme.fr"));
    }

    #[test]
    fn the_sent_text_is_redacted_and_the_attestation_kept() {
        let attestation = len_field(17, &len_field(1, &[len_field(2, b"user"), len_field(3, &[0xab; 32])].concat()));
        let context = len_field(1, &[len_field(2, b"conversation-uuid"), attestation.clone()].concat());
        let send = |text: &[u8]| len_field(2, &[len_field(1, b"message-uuid"), len_field(3, text), len_field(7, &len_field(2, b"claude-opus-5-5"))].concat());
        let body = [context.clone(), send(b"Mon email est jean.dupont@acme.fr")].concat();
        let out = redact_request(&body, &mut redact).unwrap().unwrap();
        assert_eq!(out, [context.clone(), send(b"Mon email est [EMAIL_1]")].concat());
        assert_eq!(redact_request(&[context, send(b"Bonjour")].concat(), &mut redact).unwrap(), None);
    }

    #[test]
    fn the_text_of_every_inline_attachment_is_redacted() {
        let file = |content: &[u8]| len_field(15, &[len_field(1, b"contrat.txt"), varint_field(2, 33), len_field(3, b"text/plain"), len_field(4, content)].concat());
        let send = |a: &[u8], b: &[u8]| len_field(2, &[len_field(3, b"Resume ces fichiers"), file(a), file(b)].concat());
        let out = redact_request(&send(b"Email : jean.dupont@acme.fr", b"rien"), &mut redact).unwrap().unwrap();
        assert_eq!(out, send(b"Email : [EMAIL_1]", b"rien"));
    }

    #[test]
    fn a_request_that_is_not_protobuf_is_refused() {
        assert_eq!(redact_request(b"{\"json\":true}", &mut redact), Err(Malformed));
    }

    #[test]
    fn every_token_of_a_timeline_message_is_restored() {
        let block = [len_field(1, b"block-id"), varint_field(3, 0), len_field(9, b"Ton email : [EMAIL_1], [IBAN_9] inconnu")].concat();
        let message = len_field(1, &[len_field(2, &len_field(2, b"Email [EMAIL_1]")), len_field(5, &block)].concat());
        let out = detokenize_message(&message, &mut resolve).unwrap();
        let block = [len_field(1, b"block-id"), varint_field(3, 0), len_field(9, b"Ton email : jean.dupont@acme.fr, [IBAN_9] inconnu")].concat();
        assert_eq!(out, len_field(1, &[len_field(2, &len_field(2, b"Email jean.dupont@acme.fr")), len_field(5, &block)].concat()));
        assert_eq!(detokenize_message(&len_field(9, b"rien a remplacer"), &mut resolve), None);
    }

    #[test]
    fn a_token_split_across_deltas_is_restored_whole() {
        let delta = |text: &str| len_field(1, &[varint_field(11, 2), len_field(2, &[len_field(1, b"cblk_1"), len_field(2, text.as_bytes())].concat())].concat());
        let mut timeline = TimelineDetokenizer::default();
        let mut texts = vec![];
        for piece in ["Ton email : [EMA", "IL_1], ", "voila."] {
            let out = timeline.message(&delta(piece), &mut resolve).unwrap_or_else(|| delta(piece));
            texts.push(protobuf::string_at(&out, &[1, 2, 2]).unwrap().to_owned());
        }
        assert_eq!(texts, ["Ton email : ", "jean.dupont@acme.fr, ", "voila."]);

        // A snapshot of the block carries its text whole: what was held back is dropped.
        timeline.message(&delta("puis [EMA"), &mut resolve);
        let snapshot = len_field(1, &len_field(1, &len_field(5, &[len_field(1, b"cblk_1"), len_field(9, b"Ton email : [EMAIL_1]")].concat())));
        let out = timeline.message(&snapshot, &mut resolve).unwrap();
        assert_eq!(protobuf::string_at(&out, &[1, 1, 5, 9]), Some("Ton email : jean.dupont@acme.fr"));
        let out = timeline.message(&delta("IL_1]"), &mut resolve);
        assert_eq!(out, None, "the delta after the snapshot starts afresh");
    }
}
