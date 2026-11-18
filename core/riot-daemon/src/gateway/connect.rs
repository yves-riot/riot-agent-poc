//! Connect's streaming framing (`application/connect+proto`): each message is a flags byte, its
//! length (big-endian u32) and its payload. Flag 1: the payload is compressed with the stream's
//! `Connect-Content-Encoding`; flag 2: the end-of-stream message (JSON: error and trailers).
//!
//! A rewritten message is sent on uncompressed (flag 0), which Connect allows in any stream.
//! A message left as it was keeps its bytes, compressed or not.

use std::io::Read;

const COMPRESSED: u8 = 1;
const END_STREAM: u8 = 2;
/// Larger messages are not buffered: from one on, the rest of the stream passes as it is.
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

pub struct EnvelopeRewriter {
    buffer: Vec<u8>,
    /// Whether flagged messages are gzip (`Connect-Content-Encoding: gzip`), the only encoding
    /// read; others pass unread.
    gzip: bool,
    passthrough: bool,
}

impl EnvelopeRewriter {
    pub fn new(gzip: bool) -> Self {
        Self { buffer: vec![], gzip, passthrough: false }
    }

    /// The complete messages in what has arrived, each through `rewrite` (`None`: unchanged).
    pub fn push(&mut self, chunk: &[u8], rewrite: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>) -> Vec<u8> {
        if self.passthrough {
            return chunk.to_vec();
        }
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(self.buffer.len());
        let mut at = 0;
        while let Some(header) = self.buffer.get(at..at + 5) {
            let flags = header[0];
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            if len > MAX_MESSAGE_BYTES {
                tracing::warn!(len, "connect message too large to read: the rest of the stream passes as it is");
                self.passthrough = true;
                out.extend_from_slice(&self.buffer[at..]);
                at = self.buffer.len();
                break;
            }
            let Some(payload) = self.buffer.get(at + 5..at + 5 + len) else { break };
            let raw = &self.buffer[at..at + 5 + len];
            match self.message(flags, payload).and_then(|message| rewrite(&message)) {
                Some(new) => {
                    out.push(flags & !COMPRESSED);
                    out.extend_from_slice(&(new.len() as u32).to_be_bytes());
                    out.extend_from_slice(&new);
                }
                None => out.extend_from_slice(raw),
            }
            at += 5 + len;
        }
        self.buffer.drain(..at);
        out
    }

    /// What is left of a stream that ended inside a message: passed as it is.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    /// The payload of a data message, decompressed; `None` for the end-of-stream message or an
    /// encoding not read.
    fn message(&self, flags: u8, payload: &[u8]) -> Option<Vec<u8>> {
        if flags & END_STREAM != 0 {
            return None;
        }
        if flags & COMPRESSED == 0 {
            return Some(payload.to_vec());
        }
        if !self.gzip {
            return None;
        }
        let mut out = vec![];
        flate2::read::GzDecoder::new(payload).take(MAX_MESSAGE_BYTES as u64).read_to_end(&mut out).ok()?;
        Some(out)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    pub fn envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
        [vec![flags], (payload.len() as u32).to_be_bytes().to_vec(), payload.to_vec()].concat()
    }

    pub fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn shout(message: &[u8]) -> Option<Vec<u8>> {
        message.starts_with(b"hi").then(|| message.to_ascii_uppercase())
    }

    #[test]
    fn messages_split_anywhere_are_rewritten_whole() {
        let stream = [envelope(0, b"hi there"), envelope(0, b"left alone"), envelope(1, &gzip(b"hi gzip")), envelope(2, b"{}")].concat();
        let expected = [envelope(0, b"HI THERE"), envelope(0, b"left alone"), envelope(0, b"HI GZIP"), envelope(2, b"{}")].concat();
        for split in 1..stream.len() {
            let mut rewriter = EnvelopeRewriter::new(true);
            let mut out = rewriter.push(&stream[..split], &mut shout);
            out.extend(rewriter.push(&stream[split..], &mut shout));
            out.extend(rewriter.finish());
            assert_eq!(out, expected, "split at {split}");
        }
    }

    #[test]
    fn a_compressed_message_in_an_encoding_not_read_passes_as_it_is() {
        let stream = envelope(1, b"hi, br bytes");
        assert_eq!(EnvelopeRewriter::new(false).push(&stream, &mut shout), stream);
    }

    #[test]
    fn a_stream_cut_inside_a_message_passes_what_is_left() {
        let mut rewriter = EnvelopeRewriter::new(false);
        let cut = &envelope(0, b"hi there")[..7];
        assert!(rewriter.push(cut, &mut shout).is_empty());
        assert_eq!(rewriter.finish(), cut);
    }
}
