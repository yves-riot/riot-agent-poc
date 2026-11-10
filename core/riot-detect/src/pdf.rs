//! Native pdf text extraction, standing in for pdf.js. Returns the same segments the extension's
//! `pdf-text.ts` collects: page text, then each annotation's contents, then form-field values.

use std::panic::{AssertUnwindSafe, catch_unwind};

use lopdf::{Dictionary, Document, Object};

/// Text segments of a pdf. Errors carry messages `scanErrorKind` can classify
/// ("password" → password-protected).
pub fn segments(bytes: &[u8]) -> Result<Vec<String>, String> {
    // pdf-extract and lopdf both panic on some malformed inputs; a panic must read as an
    // extraction error (fail closed), never take the engine thread down.
    catch_unwind(AssertUnwindSafe(|| extract(bytes))).unwrap_or_else(|_| Err("pdf parser panicked".into()))
}

fn extract(bytes: &[u8]) -> Result<Vec<String>, String> {
    let doc = Document::load_mem(bytes).map_err(|e| describe(&e.to_string()))?;
    if doc.is_encrypted() {
        // Owner-password-only files open with the empty user password; anything else is locked.
        if pdf_extract::extract_text_from_mem_by_pages_encrypted(bytes, "").is_err() {
            return Err("pdf is password protected".into());
        }
    }

    let pages = if doc.is_encrypted() {
        pdf_extract::extract_text_from_mem_by_pages_encrypted(bytes, "")
    } else {
        pdf_extract::extract_text_from_mem_by_pages(bytes)
    }
    .map_err(|e| describe(&e.to_string()))?;

    let mut out = Vec::new();
    for (i, (_, page_id)) in doc.get_pages().into_iter().enumerate() {
        if let Some(text) = pages.get(i) {
            let text = text.trim_matches('\u{c}').trim_end().to_string();
            if !text.is_empty() {
                out.push(text);
            }
        }
        for contents in annotation_contents(&doc, page_id) {
            if !contents.trim().is_empty() {
                out.push(contents);
            }
        }
    }
    out.extend(field_values(&doc));
    Ok(out)
}

fn describe(message: &str) -> String {
    if message.to_ascii_lowercase().contains("decrypt") || message.to_ascii_lowercase().contains("password") {
        "pdf is password protected".into()
    } else {
        format!("pdf structure error: {message}")
    }
}

fn deref<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Object> {
    doc.dereference(obj).ok().map(|(_, o)| o)
}

fn dict<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Dictionary> {
    deref(doc, obj).and_then(|o| o.as_dict().ok())
}

fn annotation_contents(doc: &Document, page_id: lopdf::ObjectId) -> Vec<String> {
    let Ok(page) = doc.get_dictionary(page_id) else { return vec![] };
    let Some(annots) = page.get(b"Annots").ok().and_then(|a| deref(doc, a)).and_then(|a| a.as_array().ok()) else {
        return vec![];
    };
    annots
        .iter()
        .filter_map(|a| dict(doc, a))
        .filter_map(|a| a.get(b"Contents").ok().and_then(|c| deref(doc, c)).and_then(text_string))
        .collect()
}

/// Values of every terminal AcroForm field (walking `Kids`), multi-select arrays flattened.
fn field_values(doc: &Document) -> Vec<String> {
    let Some(fields) = doc
        .catalog()
        .ok()
        .and_then(|c| c.get(b"AcroForm").ok())
        .and_then(|f| dict(doc, f))
        .and_then(|f| f.get(b"Fields").ok())
        .and_then(|f| deref(doc, f))
        .and_then(|f| f.as_array().ok())
    else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut stack: Vec<&Object> = fields.iter().collect();
    let mut seen = 0usize;
    while let Some(obj) = stack.pop() {
        seen += 1;
        if seen > 10_000 {
            break; // cyclic or absurd field trees
        }
        let Some(field) = dict(doc, obj) else { continue };
        if let Some(value) = field.get(b"V").ok().and_then(|v| deref(doc, v)) {
            match value {
                Object::Array(items) => out.extend(items.iter().filter_map(|i| deref(doc, i)).filter_map(text_string)),
                other => out.extend(text_string(other)),
            }
        }
        if let Some(kids) = field.get(b"Kids").ok().and_then(|k| deref(doc, k)).and_then(|k| k.as_array().ok()) {
            stack.extend(kids.iter().rev());
        }
    }
    out.retain(|v| !v.is_empty());
    out
}

/// A pdf text string: UTF-16BE with BOM, UTF-8 with BOM, else PDFDocEncoding (≈ Latin-1).
fn text_string(obj: &Object) -> Option<String> {
    let bytes = match obj {
        Object::String(bytes, _) => bytes.as_slice(),
        Object::Name(name) => name.as_slice(),
        _ => return None,
    };
    Some(if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    } else if let Some(rest) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        bytes.iter().map(|&b| b as char).collect()
    })
}
