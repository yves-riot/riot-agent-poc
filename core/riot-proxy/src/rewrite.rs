//! What a matched rule does to a request body: redact the text of a JSON body, or have the
//! files of an upload scanned.

use base64::Engine;
use bytes::Bytes;
use futures_util::stream;
use serde_json::Value;

use crate::rules::{glob, segments};
use crate::{FileVerdict, Flow, Inspector, Upload, proto};

/// Shorter strings hold nothing the engine detects, and a body has many of them.
const MIN_TEXT_CHARS: usize = 4;

/// The strings of a JSON body a rule looks at (see `RuleKind::JsonText`).
#[derive(Clone, Copy)]
pub(crate) struct Pointers<'a> {
    pub text: &'a [String],
    pub files: &'a [String],
}

pub(crate) enum Json {
    /// Forward the original bytes: nothing to change, or the body is not JSON.
    Unchanged,
    Redacted(Bytes),
    /// A file the body embeds was denied.
    Denied,
}

/// Has the files a JSON body embeds scanned, then redacts its text.
pub(crate) async fn json<I: Inspector>(inspector: &I, flow: &Flow, pointers: Pointers<'_>, history: bool, body: &[u8]) -> Json {
    let Ok(mut json) = serde_json::from_slice::<Value>(body) else { return Json::Unchanged };
    let text: Vec<Vec<&str>> = pointers.text.iter().map(|p| segments(p)).collect();
    let files: Vec<Vec<&str>> = pointers.files.iter().map(|p| segments(p)).collect();
    let selects = |patterns: &[Vec<&str>], path: &[&str]| patterns.iter().any(|p| glob(p, path));

    let mut uploads = vec![];
    if !files.is_empty() {
        visit(&mut json, &mut vec![], &mut |path, s| {
            if selects(&files, path) {
                uploads.extend(embedded_file(s));
            }
        });
    }
    for upload in uploads {
        if inspector.file(flow, upload).await == FileVerdict::Deny {
            return Json::Denied;
        }
    }

    // Text: what the text pointers select (every string when there is none), and what a file
    // pointer selects that turned out not to be a file.
    let is_text = |path: &[&str], s: &str| {
        let wanted = if selects(&files, path) { !is_base64(s) } else { text.is_empty() || selects(&text, path) };
        wanted && s.chars().count() >= MIN_TEXT_CHARS
    };
    let mut texts = vec![];
    visit(&mut json, &mut vec![], &mut |path, s| {
        if is_text(path, s) {
            texts.push(s.clone());
        }
    });
    if texts.is_empty() {
        return Json::Unchanged;
    }
    let mut replacements = inspector.text(flow, texts, history).await.into_iter();
    let mut changed = false;
    visit(&mut json, &mut vec![], &mut |path, s| {
        if is_text(path, s)
            && let Some(Some(replacement)) = replacements.next()
        {
            *s = replacement;
            changed = true;
        }
    });
    match serde_json::to_vec(&json) {
        Ok(redacted) if changed => Json::Redacted(redacted.into()),
        _ => Json::Unchanged,
    }
}

/// Redacts the strings of a protobuf body that `fields` select (see `RuleKind::ProtoText`).
/// `None` when nothing changed, or the body is not protobuf: the original bytes are forwarded.
pub(crate) async fn proto_text<I: Inspector>(inspector: &I, flow: &Flow, fields: &[String], body: &[u8]) -> Option<Bytes> {
    let paths: Vec<Vec<u64>> = fields.iter().filter_map(|f| proto::path(f)).collect();
    let paths: Vec<&[u64]> = paths.iter().map(Vec::as_slice).collect();
    let is_text = |s: &str| s.chars().count() >= MIN_TEXT_CHARS;

    let mut texts = vec![];
    proto::map_strings(body, &paths, &mut |s| {
        if is_text(s) {
            texts.push(s.to_owned());
        }
        None
    })?;
    if texts.is_empty() {
        return None;
    }
    let mut replacements = inspector.text(flow, texts, false).await.into_iter();
    let mut changed = false;
    let redacted = proto::map_strings(body, &paths, &mut |s| {
        let replacement = is_text(s).then(|| replacements.next()).flatten().flatten();
        changed |= replacement.is_some();
        replacement
    })?;
    changed.then(|| redacted.into())
}

/// Calls `f` on every string with its path, depth first, in document order.
fn visit(value: &mut Value, path: &mut Vec<String>, f: &mut impl FnMut(&[&str], &mut String)) {
    match value {
        Value::String(s) => {
            let here: Vec<&str> = path.iter().map(String::as_str).collect();
            f(&here, s);
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                path.push(i.to_string());
                visit(item, path, f);
                path.pop();
            }
        }
        Value::Object(fields) => {
            for (key, item) in fields.iter_mut() {
                // A JSON pointer escapes `~` and `/` in a key.
                path.push(key.replace('~', "~0").replace('/', "~1"));
                visit(item, path, f);
                path.pop();
            }
        }
        _ => {}
    }
}

/// `data:application/pdf;base64,JVBERi0…` → its mime and `JVBERi0…`; a bare string has no mime.
fn base64_payload(text: &str) -> (&str, &str) {
    text.strip_prefix("data:").and_then(|rest| rest.split_once(";base64,")).unwrap_or(("", text))
}

fn is_base64(text: &str) -> bool {
    let encoded = base64_payload(text).1;
    !encoded.is_empty() && encoded.len().is_multiple_of(4) && encoded.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// The file a string holds in base64, named for the engine, which picks its extractor by
/// extension. Nothing tells the name: the content does.
fn embedded_file(text: &str) -> Option<Upload> {
    let (declared, encoded) = base64_payload(text);
    if !is_base64(text) {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    let (extension, mime) = if bytes.starts_with(b"%PDF-") {
        ("pdf", "application/pdf")
    } else if bytes.starts_with(b"PK\x03\x04") && has(b"word/document.xml") {
        ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    } else if bytes.starts_with(b"PK\x03\x04") && has(b"xl/workbook.xml") {
        ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    } else if std::str::from_utf8(&bytes).is_ok() {
        ("txt", "text/plain")
    } else {
        ("bin", declared) // an image, or anything else the engine does not read
    };
    Some(Upload { name: format!("upload.{extension}"), mime: mime.to_owned(), bytes: Some(bytes.into()) })
}

/// One part of a `multipart/form-data` body, without its content.
pub(crate) struct Part {
    pub name: String,
    /// The file name, when the part is a file.
    pub file_name: Option<String>,
    pub mime: String,
    pub bytes: Bytes,
}

pub(crate) async fn multipart_parts(content_type: &str, body: Bytes) -> Result<Vec<Part>, multer::Error> {
    let boundary = multer::parse_boundary(content_type)?;
    let mut multipart = multer::Multipart::new(stream::once(async move { Ok::<_, std::convert::Infallible>(body) }), boundary);
    let mut parts = vec![];
    while let Some(field) = multipart.next_field().await? {
        parts.push(Part {
            name: field.name().unwrap_or_default().to_owned(),
            file_name: field.file_name().map(str::to_owned),
            mime: field.content_type().map(|m| m.essence_str().to_owned()).unwrap_or_default(),
            bytes: field.bytes().await?,
        });
    }
    Ok(parts)
}

/// Has every file of a multipart upload scanned. One denied file denies the request; so does a
/// body that cannot be parsed, since what could not be read is not known to be clean.
pub(crate) async fn multipart_files<I: Inspector>(inspector: &I, flow: &Flow, content_type: &str, body: Bytes) -> FileVerdict {
    let parts = match multipart_parts(content_type, body).await {
        Ok(parts) => parts,
        Err(e) => {
            tracing::warn!(host = %flow.host, error = %e, "unreadable multipart upload");
            return inspector.file(flow, Upload { name: String::new(), mime: String::new(), bytes: None }).await;
        }
    };
    for part in parts {
        let Some(name) = part.file_name else { continue };
        let upload = Upload { name, mime: part.mime, bytes: Some(part.bytes) };
        if inspector.file(flow, upload).await == FileVerdict::Deny {
            return FileVerdict::Deny;
        }
    }
    FileVerdict::Allow
}

/// The name to scan a raw upload under: the engine picks its extractor by extension. The URL
/// rarely carries one, the content type does.
pub(crate) fn raw_file_name(path: &str, mime: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or_default();
    if last.rsplit_once('.').is_some_and(|(stem, ext)| !stem.is_empty() && (1..=5).contains(&ext.len())) {
        return last.to_owned();
    }
    let extension = match mime {
        "application/pdf" => "pdf",
        "text/plain" => "txt",
        "text/csv" => "csv",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        _ => return "upload".into(),
    };
    format!("upload.{extension}")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Rule;

    /// Replaces `SECRET` with `[X_1]`.
    struct Fake;

    impl Inspector for Fake {
        fn rules(&self, _: &Flow) -> Option<Arc<[Rule]>> {
            None
        }
        async fn text(&self, _: &Flow, texts: Vec<String>, _: bool) -> Vec<Option<String>> {
            texts.into_iter().map(|t| t.contains("SECRET").then(|| t.replace("SECRET", "[X_1]"))).collect()
        }
        /// Denies the PDFs that hold `SECRET`.
        async fn file(&self, _: &Flow, upload: Upload) -> FileVerdict {
            let bytes = upload.bytes.unwrap();
            if upload.name == "upload.pdf" && bytes.windows(6).any(|w| w == b"SECRET") { FileVerdict::Deny } else { FileVerdict::Allow }
        }
    }

    fn flow() -> Flow {
        Flow { host: "ai.test".into(), port: 443, bundle_id: None, uid: None, pid: None }
    }

    async fn rewrite(text: &[&str], files: &[&str], body: &str) -> Json {
        let text: Vec<String> = text.iter().map(|p| p.to_string()).collect();
        let files: Vec<String> = files.iter().map(|p| p.to_string()).collect();
        json(&Fake, &flow(), Pointers { text: &text, files: &files }, false, body.as_bytes()).await
    }

    async fn redact(pointers: &[&str], body: &str) -> Option<String> {
        match rewrite(pointers, &[], body).await {
            Json::Redacted(out) => Some(String::from_utf8(out.to_vec()).unwrap()),
            Json::Unchanged => None,
            Json::Denied => panic!("denied"),
        }
    }

    #[tokio::test]
    async fn redacts_only_the_selected_strings_and_keeps_the_key_order() {
        let body = r#"{"z":"SECRET id","prompt":"my SECRET","messages":[{"content":{"parts":["a SECRET",7]}}],"n":1.5}"#;
        assert_eq!(
            redact(&["/prompt", "/messages/*/content/parts/*"], body).await.unwrap(),
            r#"{"z":"SECRET id","prompt":"my [X_1]","messages":[{"content":{"parts":["a [X_1]",7]}}],"n":1.5}"#
        );
        assert_eq!(
            redact(&[], body).await.unwrap(),
            r#"{"z":"[X_1] id","prompt":"my [X_1]","messages":[{"content":{"parts":["a [X_1]",7]}}],"n":1.5}"#
        );
    }

    #[tokio::test]
    async fn leaves_the_body_alone_when_nothing_changes() {
        assert_eq!(redact(&["/prompt"], r#"{"prompt":"nothing here"}"#).await, None);
        assert_eq!(redact(&["/other"], r#"{"prompt":"my SECRET"}"#).await, None);
        assert_eq!(redact(&[], "not json SECRET").await, None);
    }

    #[tokio::test]
    async fn redacts_the_strings_of_a_protobuf_body() {
        use crate::proto::tests::len;
        let body = |text: &str| [len(1, b"conversation"), len(2, &[len(1, b"SECRET-id"), len(3, text.as_bytes())].concat())].concat();
        let fields = ["2.3".to_owned()];
        let redacted = proto_text(&Fake, &flow(), &fields, &body("my SECRET")).await.unwrap();
        assert_eq!(redacted, body("my [X_1]"));
        assert_eq!(proto_text(&Fake, &flow(), &fields, &body("nothing here")).await, None);
        assert_eq!(proto_text(&Fake, &flow(), &fields, b"SECRET, but not protobuf").await, None);
        assert_eq!(proto_text(&Fake, &flow(), &["nonsense".to_owned()], &body("my SECRET")).await, None);
    }

    #[tokio::test]
    async fn scans_the_files_a_body_embeds() {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let body = |data: &str| format!(r#"{{"messages":[{{"content":[{{"type":"document","source":{{"type":"base64","data":"{data}"}}}}]}}]}}"#);
        let (text, files) = (["/messages/*/content/*/text"], ["/messages/*/content/*/source/data"]);

        assert!(matches!(rewrite(&text, &files, &body(&b64(b"%PDF-1.7 a SECRET"))).await, Json::Denied));
        let url = format!("data:application/pdf;base64,{}", b64(b"%PDF-1.7 a SECRET"));
        assert!(matches!(rewrite(&text, &files, &body(&url)).await, Json::Denied));
        assert!(matches!(rewrite(&text, &files, &body(&b64(b"%PDF-1.7 nothing"))).await, Json::Unchanged));
        // Base64 is not text: it is not handed to the redaction, even when every string is.
        assert!(matches!(rewrite(&[], &files, &body(&b64(b"\x89PNG SECRET"))).await, Json::Unchanged));
        // A document given as plain text is redacted like the rest.
        let Json::Redacted(out) = rewrite(&text, &files, &body("my SECRET, as text")).await else { panic!() };
        assert!(String::from_utf8(out.to_vec()).unwrap().contains(r#""data":"my [X_1], as text""#));
        // Without a file pointer the same string is nobody's business.
        assert!(matches!(rewrite(&text, &[], &body(&b64(b"%PDF-1.7 a SECRET"))).await, Json::Unchanged));
    }

    #[test]
    fn names_an_embedded_file_by_its_content() {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let name = |bytes: &[u8]| embedded_file(&b64(bytes)).unwrap().name;
        assert_eq!(name(b"%PDF-1.7"), "upload.pdf");
        assert_eq!(name(b"PK\x03\x04 [Content_Types].xml word/document.xml"), "upload.docx");
        assert_eq!(name(b"PK\x03\x04 [Content_Types].xml xl/workbook.xml"), "upload.xlsx");
        assert_eq!(name(b"name,iban\n"), "upload.txt");
        assert_eq!(name(b"\x89PNG\r\n\x1a\n\xff"), "upload.bin");
        assert!(embedded_file("not base64 at all").is_none());
        assert!(embedded_file("").is_none());
    }

    #[tokio::test]
    async fn reads_multipart_parts() {
        let body = "--XX\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n\
                    --XX\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"\r\n\
                    Content-Type: application/pdf\r\n\r\n%PDF\r\n--XX--\r\n";
        let parts = multipart_parts("multipart/form-data; boundary=XX", Bytes::from(body)).await.unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!((parts[0].name.as_str(), parts[0].file_name.as_deref()), ("note", None));
        assert_eq!(parts[1].file_name.as_deref(), Some("a.pdf"));
        assert_eq!(parts[1].mime, "application/pdf");
        assert_eq!(&parts[1].bytes[..], b"%PDF");
        assert!(multipart_parts("multipart/form-data", Bytes::new()).await.is_err());
    }

    #[test]
    fn names_a_raw_upload_for_the_engine() {
        assert_eq!(raw_file_name("/files/report.pdf", ""), "report.pdf");
        assert_eq!(raw_file_name("/files/0f3a", "application/pdf"), "upload.pdf");
        assert_eq!(raw_file_name("/files/0f3a", "image/png"), "upload");
    }
}
