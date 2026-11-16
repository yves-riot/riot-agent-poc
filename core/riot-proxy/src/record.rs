//! Record mode (`ProxyConfig::record`): logs the shape of each request to a protected host, to
//! write the rules from what the apps really send. Shapes only: keys, types and lengths, never
//! a value.

use serde_json::Value;

use crate::proto::next_field;
use crate::rewrite::Part;

const MAX_SHAPE: usize = 2000;

/// `{"prompt":"hello","files":[{"id":"a"}],"n":1}` → `{prompt:str(5),files:[1×{id:str(1)}],n:num}`
pub(crate) fn json_shape(body: &[u8]) -> Option<String> {
    let json: Value = serde_json::from_slice(body).ok()?;
    let mut out = String::new();
    shape(&json, &mut out);
    Some(cut(out))
}

fn shape(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(_) => out.push_str("bool"),
        Value::Number(_) => out.push_str("num"),
        Value::String(s) => out.push_str(&format!("str({})", s.chars().count())),
        Value::Array(items) => {
            out.push_str(&format!("[{}×", items.len()));
            // One shape per kind of item (a message's blocks differ), lengths aside.
            let mut kinds: Vec<String> = vec![];
            for item in items {
                let mut one = String::new();
                shape(item, &mut one);
                let kind: String = one.chars().filter(|c| !c.is_ascii_digit()).collect();
                if !kinds.contains(&kind) {
                    if !kinds.is_empty() {
                        out.push('|');
                    }
                    out.push_str(&one);
                    kinds.push(kind);
                }
            }
            out.push(']');
        }
        Value::Object(fields) => {
            out.push('{');
            for (i, (key, item)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(key);
                out.push(':');
                shape(item, out);
            }
            out.push('}');
        }
    }
}

/// A protobuf message read without its schema: field numbers, kinds and lengths.
/// `{1:str(36),2:{1:str(57),3:int},4:bytes(1024)}`. A field is taken for text when it is
/// printable, for a message when it parses as one, for bytes otherwise.
pub(crate) fn proto_shape(body: &[u8]) -> Option<String> {
    let mut out = String::new();
    proto(body, 0, &mut out)?;
    Some(cut(out))
}

/// The same for a Connect stream: each message comes after a flag byte and its length.
pub(crate) fn connect_shape(mut body: &[u8]) -> Option<String> {
    let mut out = String::new();
    while !body.is_empty() {
        let (head, rest) = body.split_at_checked(5)?;
        let (message, rest) = rest.split_at_checked(u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize)?;
        // Flag 2 ends the stream with JSON metadata, flag 1 is a compressed message.
        match head[0] {
            0 => proto(message, 0, &mut out)?,
            flags => out.push_str(&format!("frame(flags {flags}, {})", message.len())),
        }
        body = rest;
    }
    Some(cut(out))
}

fn cut(mut out: String) -> String {
    if out.len() > MAX_SHAPE {
        let cut = (0..=MAX_SHAPE).rev().find(|i| out.is_char_boundary(*i)).unwrap_or(0);
        out.truncate(cut);
        out.push('…');
    }
    out
}

fn proto(mut buf: &[u8], depth: usize, out: &mut String) -> Option<()> {
    out.push('{');
    let mut first = true;
    while !buf.is_empty() {
        let field = next_field(&mut buf)?;
        if !std::mem::take(&mut first) {
            out.push(',');
        }
        out.push_str(&format!("{}:", field.number));
        let Some(value) = field.payload else {
            out.push_str(field.kind);
            continue;
        };
        let printable = std::str::from_utf8(value).ok().filter(|s| !s.chars().any(|c| c.is_control() && !c.is_whitespace()));
        let mut nested = String::new();
        if let Some(text) = printable {
            out.push_str(&format!("str({})", text.chars().count()));
        } else if depth < 16 && proto(value, depth + 1, &mut nested).is_some() {
            out.push_str(&nested);
        } else {
            out.push_str(&format!("bytes({})", value.len()));
        }
    }
    out.push('}');
    Some(())
}

/// `note:text(5) file:file(.pdf application/pdf 1024)`: a file name is content, its extension
/// is not.
pub(crate) fn multipart_shape(parts: &[Part]) -> String {
    parts
        .iter()
        .map(|p| match &p.file_name {
            Some(name) => {
                let ext = name.rsplit_once('.').map_or("", |(_, ext)| ext);
                format!("{}:file(.{ext} {} {})", p.name, p.mime, p.bytes.len())
            }
            None => format!("{}:text({})", p.name, p.bytes.len()),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_hold_no_value() {
        let body = br#"{"prompt":"hello","files":[{"id":"a"},{"id":"bc"},{"text":"d"}],"n":1,"ok":true,"none":null,"empty":[]}"#;
        assert_eq!(
            json_shape(body).unwrap(),
            "{prompt:str(5),files:[3×{id:str(1)}|{text:str(1)}],n:num,ok:bool,none:null,empty:[0×]}"
        );
        assert_eq!(json_shape(b"plain text"), None);
    }

    #[test]
    fn protobuf_shapes_hold_no_value() {
        // { 1: "hello", 2: { 1: "a b", 3: 150 }, 4: bytes, 5: fixed32 }
        let mut body = vec![0x0a, 5];
        body.extend(b"hello");
        body.extend([0x12, 8, 0x0a, 3]);
        body.extend(b"a b");
        body.extend([0x18, 0x96, 0x01]);
        body.extend([0x22, 3, 0xff, 0x00, 0x01]);
        body.extend([0x2d, 1, 2, 3, 4]);
        assert_eq!(proto_shape(&body).unwrap(), "{1:str(5),2:{1:str(3),3:int},4:bytes(3),5:fixed32}");
        assert_eq!(proto_shape(&body[..body.len() - 2]), None, "cut short");

        let mut stream = vec![0, 0, 0, 0, body.len() as u8];
        stream.extend(&body);
        stream.extend([2, 0, 0, 0, 2, b'{', b'}']);
        assert_eq!(
            connect_shape(&stream).unwrap(),
            "{1:str(5),2:{1:str(3),3:int},4:bytes(3),5:fixed32}frame(flags 2, 2)"
        );
    }

    #[test]
    fn long_shapes_are_cut() {
        let body = serde_json::to_vec(&(0..500).map(|i| (format!("key{i}"), serde_json::json!(1))).collect::<serde_json::Map<_, _>>()).unwrap();
        let shape = json_shape(&body).unwrap();
        assert!(shape.len() <= MAX_SHAPE + '…'.len_utf8());
        assert!(shape.ends_with('…'));
    }
}
