//! The protobuf wire format, read without a schema: enough to find a string by the field
//! numbers that lead to it, and to put another in its place.

/// One field of a message.
pub(crate) struct Field<'a> {
    pub number: u64,
    /// The field as it was encoded, key included.
    pub raw: &'a [u8],
    /// What a length-delimited field holds: a string, bytes or a message.
    pub payload: Option<&'a [u8]>,
    /// `int`, `fixed64`, `fixed32` or `len`.
    pub kind: &'static str,
}

pub(crate) fn varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Takes the next field off `buf`. `None` when what is there is not one.
pub(crate) fn next_field<'a>(buf: &mut &'a [u8]) -> Option<Field<'a>> {
    let start = *buf;
    let key = varint(buf)?;
    let number = key >> 3;
    let mut payload = None;
    let kind = match key & 7 {
        0 => varint(buf).map(|_| "int")?,
        1 => {
            *buf = buf.split_at_checked(8)?.1;
            "fixed64"
        }
        5 => {
            *buf = buf.split_at_checked(4)?.1;
            "fixed32"
        }
        2 => {
            let len = usize::try_from(varint(buf)?).ok()?;
            let (value, rest) = buf.split_at_checked(len)?;
            (*buf, payload) = (rest, Some(value));
            "len"
        }
        _ => return None, // groups: long gone
    };
    (number != 0).then(|| Field { number, raw: &start[..start.len() - buf.len()], payload, kind })
}

/// `2.3` → `[2, 3]`: field 3 of the message in field 2.
pub(crate) fn path(text: &str) -> Option<Vec<u64>> {
    text.split('.').map(|n| n.parse().ok().filter(|n| *n != 0)).collect()
}

/// Calls `f` on every string `paths` select, in the order of the message, and returns the
/// message with each string `f` gave a replacement for. A repeated field is every one of its
/// occurrences. `None` when `message` is not protobuf.
pub(crate) fn map_strings(message: &[u8], paths: &[&[u64]], f: &mut impl FnMut(&str) -> Option<String>) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(message.len());
    let mut rest = message;
    while !rest.is_empty() {
        let field = next_field(&mut rest)?;
        let here: Vec<&[u64]> = paths.iter().filter(|p| p.first() == Some(&field.number)).map(|p| &p[1..]).collect();
        let replaced = field.payload.filter(|_| !here.is_empty()).and_then(|payload| {
            if here.iter().any(|p| p.is_empty()) {
                std::str::from_utf8(payload).ok().and_then(&mut *f).map(String::into_bytes)
            } else {
                // Not a message after all: the rule is wrong about it, the field stays as it is.
                map_strings(payload, &here, f)
            }
        });
        match replaced {
            Some(payload) => {
                put_varint(&mut out, field.number << 3 | 2);
                put_varint(&mut out, payload.len() as u64);
                out.extend(payload);
            }
            None => out.extend(field.raw),
        }
    }
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A length-delimited field.
    pub(crate) fn len(number: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        put_varint(&mut out, number << 3 | 2);
        put_varint(&mut out, payload.len() as u64);
        out.extend(payload);
        out
    }

    fn message() -> Vec<u8> {
        // { 1: { 2: "conversation" }, 2: { 1: "id", 3: "my SECRET", 3: "another SECRET", 4: 150 }, 3: "a SECRET too" }
        let inner = [len(1, b"id"), len(3, b"my SECRET"), len(3, b"another SECRET"), vec![0x20, 0x96, 0x01]].concat();
        [len(1, &len(2, b"conversation")), len(2, &inner), len(3, b"a SECRET too")].concat()
    }

    #[test]
    fn replaces_the_selected_strings_and_recomputes_the_lengths() {
        let mut seen = vec![];
        let redacted = map_strings(&message(), &[&[2, 3]], &mut |s| {
            seen.push(s.to_owned());
            Some(s.replace("SECRET", "[X_1]"))
        })
        .unwrap();
        assert_eq!(seen, ["my SECRET", "another SECRET"]);
        let inner = [len(1, b"id"), len(3, b"my [X_1]"), len(3, b"another [X_1]"), vec![0x20, 0x96, 0x01]].concat();
        assert_eq!(redacted, [len(1, &len(2, b"conversation")), len(2, &inner), len(3, b"a SECRET too")].concat());
    }

    #[test]
    fn leaves_alone_what_it_does_not_change_or_cannot_read() {
        let message = message();
        assert_eq!(map_strings(&message, &[&[2, 3]], &mut |_| None).unwrap(), message);
        assert_eq!(map_strings(&message, &[&[9, 9]], &mut |_| panic!()).unwrap(), message);
        // Field 3 holds a string, not a message: nothing under it.
        assert_eq!(map_strings(&message, &[&[3, 1]], &mut |_| panic!()).unwrap(), message);
        // A string that grows past one length byte.
        let long = map_strings(&message, &[&[3]], &mut |_| Some("x".repeat(300))).unwrap();
        assert!(long.ends_with(&len(3, "x".repeat(300).as_bytes())));
        assert!(map_strings(&message[..message.len() - 3], &[&[2, 3]], &mut |_| None).is_none(), "cut short");
        assert!(map_strings(b"plain text, not protobuf", &[&[2, 3]], &mut |_| None).is_none());
    }

    #[test]
    fn reads_paths() {
        assert_eq!(path("2.3"), Some(vec![2, 3]));
        assert_eq!(path("7"), Some(vec![7]));
        for wrong in ["", "2.", "a.b", "0.1", "/2/3"] {
            assert_eq!(path(wrong), None, "{wrong}");
        }
    }
}
