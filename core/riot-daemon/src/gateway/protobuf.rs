//! The Protocol Buffers wire format, read and rewritten without a schema: Claude Desktop's is
//! not published. A rewritten message keeps every byte it did not change (unknown fields, field
//! order); only the strings changed and the lengths of the messages around them differ.
//!
//! On the wire a length-delimited field is a string, bytes or a nested message alike. Where the
//! path is known (`rewrite_at`) the caller says which; elsewhere (`rewrite_strings`) a field that
//! parses as a message is taken as one, else as a string. A message is the safe guess: a nested
//! message can be all printable bytes (`J(` then 40 characters is field 9 holding them), and
//! taking it as a string would change its text without its length. Text that happens to parse
//! as a message is left as it is, unless a whole token falls inside one of its would-be fields.

/// Nested messages deeper than this are taken as opaque bytes.
const MAX_DEPTH: usize = 32;

/// Not a protobuf message: the caller refuses it rather than send it unread.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

fn varint(b: &[u8], i: &mut usize) -> Result<u64, Malformed> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*i).ok_or(Malformed)?;
        *i += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(Malformed)
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// One field of a message: its number, wire type, the whole encoded field, and for a
/// length-delimited one, its payload.
struct Field<'a> {
    number: u64,
    raw: &'a [u8],
    payload: Option<&'a [u8]>,
}

fn fields(msg: &[u8]) -> impl Iterator<Item = Result<Field<'_>, Malformed>> {
    let mut i = 0;
    std::iter::from_fn(move || {
        if i >= msg.len() {
            return None;
        }
        let start = i;
        let field = (|| {
            let key = varint(msg, &mut i)?;
            let number = key >> 3;
            if number == 0 {
                return Err(Malformed);
            }
            let mut payload = None;
            match key & 7 {
                0 => {
                    varint(msg, &mut i)?;
                }
                1 => i += 8,
                5 => i += 4,
                2 => {
                    let len = usize::try_from(varint(msg, &mut i)?).map_err(|_| Malformed)?;
                    let end = i.checked_add(len).ok_or(Malformed)?;
                    payload = Some(msg.get(i..end).ok_or(Malformed)?);
                    i = end;
                }
                _ => return Err(Malformed),
            }
            let raw = msg.get(start..i).ok_or(Malformed)?;
            Ok(Field { number, raw, payload })
        })();
        if field.is_err() {
            i = msg.len();
        }
        Some(field)
    })
}

/// Whether `b` parses as a message: its payloads may be strings or messages alike.
fn is_message(b: &[u8], depth: usize) -> bool {
    !b.is_empty() && depth <= MAX_DEPTH && fields(b).all(|f| f.is_ok())
}

fn put_len_field(out: &mut Vec<u8>, number: u64, payload: &[u8]) {
    put_varint(out, number << 3 | 2);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Rewrites the strings at `path` (field numbers from the top message; every occurrence of a
/// repeated field). `None` when nothing changed.
pub fn rewrite_at<E: From<Malformed>>(msg: &[u8], path: &[u64], f: &mut dyn FnMut(&str) -> Result<Option<String>, E>) -> Result<Option<Vec<u8>>, E> {
    let Some((&number, rest)) = path.split_first() else { return Ok(None) };
    let mut out = Vec::with_capacity(msg.len() + 64);
    let mut changed = false;
    for field in fields(msg) {
        let field = field.map_err(E::from)?;
        let new = match field.payload {
            Some(payload) if field.number == number => match rest {
                [] => f(std::str::from_utf8(payload).map_err(|_| Malformed)?)?.map(String::into_bytes),
                _ => rewrite_at(payload, rest, f)?,
            },
            _ => None,
        };
        match new {
            Some(payload) => {
                put_len_field(&mut out, field.number, &payload);
                changed = true;
            }
            None => out.extend_from_slice(field.raw),
        }
    }
    Ok(changed.then_some(out))
}

/// The first string at `path`, if the message has one there.
pub fn string_at<'a>(msg: &'a [u8], path: &[u64]) -> Option<&'a str> {
    let (&number, rest) = path.split_first()?;
    let payload = fields(msg).map_while(Result::ok).find(|f| f.number == number)?.payload?;
    match rest {
        [] => std::str::from_utf8(payload).ok(),
        _ => string_at(payload, rest),
    }
}

/// Rewrites every string of a message, at any depth. `None` when nothing changed, or when `msg`
/// is not a message.
pub fn rewrite_strings(msg: &[u8], f: &mut dyn FnMut(&str) -> Option<String>) -> Option<Vec<u8>> {
    rewrite_strings_at(msg, f, 0)
}

fn rewrite_strings_at(msg: &[u8], f: &mut dyn FnMut(&str) -> Option<String>, depth: usize) -> Option<Vec<u8>> {
    if !is_message(msg, depth) {
        return None;
    }
    let mut out = Vec::with_capacity(msg.len() + 64);
    let mut changed = false;
    for field in fields(msg) {
        let field = field.ok()?;
        let new = field.payload.and_then(|payload| {
            if is_message(payload, depth + 1) {
                rewrite_strings_at(payload, f, depth + 1)
            } else {
                std::str::from_utf8(payload).ok().and_then(&mut *f).map(String::into_bytes)
            }
        });
        match new {
            Some(payload) => {
                put_len_field(&mut out, field.number, &payload);
                changed = true;
            }
            None => out.extend_from_slice(field.raw),
        }
    }
    changed.then_some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A field holding `payload` (a string or an encoded message).
    pub fn len_field(number: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        put_len_field(&mut out, number, payload);
        out
    }

    pub fn varint_field(number: u64, value: u64) -> Vec<u8> {
        let mut out = vec![];
        put_varint(&mut out, number << 3);
        put_varint(&mut out, value);
        out
    }

    fn upper(text: &str) -> Option<String> {
        (text.chars().any(char::is_lowercase)).then(|| text.to_uppercase())
    }

    #[test]
    fn a_string_at_a_path_is_rewritten_and_every_other_byte_kept() {
        let inner = [len_field(1, b"id-1"), len_field(3, b"hello"), varint_field(7, 300)].concat();
        let msg = [varint_field(1, 5), len_field(2, &inner), len_field(9, &[0xff, 0x00])].concat();
        let out = rewrite_at::<Malformed>(&msg, &[2, 3], &mut |t| Ok(Some(format!("{t}, world")))).unwrap().unwrap();
        let inner = [len_field(1, b"id-1"), len_field(3, b"hello, world"), varint_field(7, 300)].concat();
        assert_eq!(out, [varint_field(1, 5), len_field(2, &inner), len_field(9, &[0xff, 0x00])].concat());
        assert_eq!(rewrite_at::<Malformed>(&msg, &[2, 3], &mut |_| Ok(None)).unwrap(), None);
        assert_eq!(rewrite_at::<Malformed>(&msg, &[4, 3], &mut |_| Ok(Some("x".into()))).unwrap(), None);
    }

    #[test]
    fn a_malformed_message_is_refused() {
        let truncated = [len_field(2, b"hello")[..4].to_vec()].concat();
        assert_eq!(rewrite_at::<Malformed>(&truncated, &[2], &mut |_| Ok(None)), Err(Malformed));
        assert_eq!(rewrite_at::<Malformed>(&len_field(2, &[0xff, 0xfe]), &[2], &mut |_| Ok(None)), Err(Malformed));
    }

    #[test]
    fn every_string_is_rewritten_at_any_depth() {
        let block = [len_field(1, b"\x12\x34"), len_field(9, b"voici le texte")].concat();
        let msg = [len_field(1, &[len_field(5, &block), varint_field(3, 1)].concat()), len_field(2, b"titre")].concat();
        let out = rewrite_strings(&msg, &mut upper).unwrap();
        let block = [len_field(1, b"\x12\x34"), len_field(9, b"VOICI LE TEXTE")].concat();
        assert_eq!(out, [len_field(1, &[len_field(5, &block), varint_field(3, 1)].concat()), len_field(2, b"TITRE")].concat());
        assert_eq!(rewrite_strings(b"plain text", &mut upper), None, "not a message");
    }

    #[test]
    fn a_nested_message_of_printable_bytes_is_still_a_message() {
        // Field 9 holding 40 characters encodes as `J(` and the text: all printable.
        let text = "le texte fait quarante caracteres pile!!";
        let block = len_field(9, text.as_bytes());
        assert!(std::str::from_utf8(&block).is_ok());
        let out = rewrite_strings(&len_field(5, &block), &mut upper).unwrap();
        assert_eq!(out, len_field(5, &len_field(9, text.to_uppercase().as_bytes())));
    }
}
