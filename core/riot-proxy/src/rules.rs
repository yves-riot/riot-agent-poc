//! Which requests the proxy looks into, and how. The AI services' APIs are private and change
//! without notice, so nothing about them is compiled in: rules come with the policy (parrot),
//! and a request no rule matches is forwarded as it is.

use serde::{Deserialize, Serialize};

/// One request shape of a protected service:
///
/// ```json
/// { "host": "claude.ai", "method": "POST",
///   "path": "/api/organizations/*/chat_conversations/*/completion",
///   "kind": "json_text", "text_pointers": ["/prompt"] }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// The exact host, or `*.example.com` for its subdomains.
    pub host: String,
    /// Any method when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The path, segment by segment: `*` is any one segment, a final `**` any remainder.
    pub path: String,
    #[serde(flatten)]
    pub kind: RuleKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleKind {
    /// A JSON body carrying what the user wrote: its strings are redacted in place.
    JsonText {
        /// JSON pointers (with the path wildcards) of the strings to redact. Every string of
        /// the body when empty.
        #[serde(default)]
        text_pointers: Vec<String>,
        /// JSON pointers of the strings that hold a file in base64, bare or as a `data:` URL (a
        /// document attached to a message). Each is scanned like an upload, and one denied
        /// file refuses the request. A string that is not base64 is text, and is redacted.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        file_pointers: Vec<String>,
        /// The body repeats the conversation so far (an API that keeps no state, as Claude
        /// Code's). A text handled once is then handled the same way in every later request,
        /// and is one event, not one per request.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        history: bool,
    },
    /// A protobuf body carrying what the user wrote (a Connect call): its strings are redacted
    /// in place.
    ProtoText {
        /// The strings to redact, each by the field numbers that lead to it: `2.3` is field 3
        /// of the message in field 2. A service's schema is private; record mode shows the
        /// numbers.
        text_fields: Vec<String>,
    },
    /// A `multipart/form-data` body: each part with a filename is a file to scan.
    MultipartFile,
    /// The body is the file itself (an upload straight to blob storage).
    RawFile,
}

impl Rule {
    pub fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        host_matches(&self.host, host)
            && self.method.as_deref().is_none_or(|m| m.eq_ignore_ascii_case(method))
            && glob(&segments(&self.path), &segments(path))
    }
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.')),
        None => pattern.eq_ignore_ascii_case(host),
    }
}

/// `/a/b` → `["a", "b"]`; a JSON pointer splits the same way.
pub(crate) fn segments(path: &str) -> Vec<&str> {
    path.split('/').skip(1).collect()
}

pub(crate) fn glob(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) if pattern.len() == 1 => true,
        (Some(&p), Some(&s)) if p == "*" || p == s => glob(&pattern[1..], &path[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(json: serde_json::Value) -> Rule {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn matches_host_method_and_path() {
        let r = rule(serde_json::json!({
            "host": "claude.ai", "method": "POST",
            "path": "/api/organizations/*/chat_conversations/*/completion",
            "kind": "json_text", "text_pointers": ["/prompt"]
        }));
        assert_eq!(r.kind, RuleKind::JsonText { text_pointers: vec!["/prompt".into()], file_pointers: vec![], history: false });
        let path = "/api/organizations/o-1/chat_conversations/c-1/completion";
        assert!(r.matches("claude.ai", "POST", path));
        assert!(r.matches("CLAUDE.AI", "post", path));
        assert!(!r.matches("claude.ai", "GET", path));
        assert!(!r.matches("api.claude.ai", "POST", path));
        assert!(!r.matches("claude.ai", "POST", "/api/organizations/o-1/chat_conversations/c-1"));
        assert!(!r.matches("claude.ai", "POST", &format!("{path}/extra")));
    }

    #[test]
    fn wildcards() {
        let r = rule(serde_json::json!({ "host": "*.oaiusercontent.com", "path": "/files/**", "kind": "raw_file" }));
        assert!(r.matches("files.oaiusercontent.com", "PUT", "/files/a/b"));
        assert!(r.matches("files.oaiusercontent.com", "PUT", "/files/"));
        assert!(!r.matches("oaiusercontent.com", "PUT", "/files/a"));
        assert!(!r.matches("evil-oaiusercontent.com", "PUT", "/files/a"));
        assert!(!r.matches("files.oaiusercontent.com", "PUT", "/other"));
        assert!(glob(&segments("/messages/*/content/parts/*"), &["messages", "0", "content", "parts", "2"]));
        assert!(!glob(&segments("/messages/*/content"), &["messages", "0", "author"]));
    }
}
