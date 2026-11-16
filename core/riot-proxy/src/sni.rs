//! Reads the server name out of a TLS ClientHello without consuming it: the proxy decides from
//! it whether to terminate TLS or to relay the bytes untouched.

use tokio::io::{AsyncRead, AsyncReadExt};

const HANDSHAKE_RECORD: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SERVER_NAME_EXTENSION: u16 = 0;
const HOST_NAME: u8 = 0;
/// A TLS record's payload is at most 2^14 bytes, plus some slack older stacks allow.
const MAX_RECORD: usize = 16 * 1024 + 2048;

/// Reads the first TLS record after `buf` (bytes already read from `io`). Returns every byte
/// read so far, to replay to whoever handles the connection, and the server name when the
/// record is a ClientHello that carries one.
pub(crate) async fn read_client_hello<R: AsyncRead + Unpin>(
    io: &mut R,
    mut buf: Vec<u8>,
) -> std::io::Result<(Vec<u8>, Option<String>)> {
    fill(io, &mut buf, 5).await?;
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf[0] != HANDSHAKE_RECORD || buf[1] != 3 || len > MAX_RECORD {
        return Ok((buf, None)); // not TLS: relayed as it is
    }
    fill(io, &mut buf, 5 + len).await?;
    let name = server_name(&buf[5..5 + len]);
    Ok((buf, name))
}

async fn fill<R: AsyncRead + Unpin>(io: &mut R, buf: &mut Vec<u8>, len: usize) -> std::io::Result<()> {
    while buf.len() < len {
        let mut chunk = [0u8; 4096];
        let want = (len - buf.len()).min(chunk.len());
        let read = io.read(&mut chunk[..want]).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// The `server_name` of a ClientHello handshake message (a TLS record's payload). `None` when
/// the message is something else, is cut short (a hello spread over several records), or names
/// no host.
pub(crate) fn server_name(handshake: &[u8]) -> Option<String> {
    let mut r = Reader(handshake);
    if r.u8()? != CLIENT_HELLO {
        return None;
    }
    r.skip(3 + 2 + 32)?; // length, legacy version, random
    let session_id = r.u8()? as usize;
    r.skip(session_id)?;
    let cipher_suites = r.u16()? as usize;
    r.skip(cipher_suites)?;
    let compression = r.u8()? as usize;
    r.skip(compression)?;
    let extensions = r.u16()? as usize;
    let mut r = Reader(r.take(extensions)?);
    while let Some(kind) = r.u16() {
        let len = r.u16()? as usize;
        let body = r.take(len)?;
        if kind != SERVER_NAME_EXTENSION {
            continue;
        }
        let mut list = Reader(body);
        let list_len = list.u16()? as usize;
        let mut names = Reader(list.take(list_len)?);
        while let Some(name_type) = names.u8() {
            let len = names.u16()? as usize;
            let name = names.take(len)?;
            if name_type == HOST_NAME {
                return std::str::from_utf8(name).ok().map(str::to_ascii_lowercase);
            }
        }
    }
    None
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len)?;
        self.0 = tail;
        Some(head)
    }
    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A real ClientHello, as rustls writes it for `host`.
    fn client_hello(host: &str) -> Vec<u8> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), host.to_owned().try_into().unwrap()).unwrap();
        let mut out = vec![];
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[tokio::test]
    async fn finds_the_server_name_and_keeps_every_byte() {
        let hello = client_hello("Claude.AI");
        let mut io = std::io::Cursor::new(hello.clone());
        let (read, name) = read_client_hello(&mut io, vec![]).await.unwrap();
        assert_eq!(name.as_deref(), Some("claude.ai"));
        assert_eq!(read, hello);
    }

    #[tokio::test]
    async fn resumes_after_bytes_already_read() {
        let hello = client_hello("chatgpt.com");
        let (head, tail) = hello.split_at(3);
        let mut io = std::io::Cursor::new(tail.to_vec());
        let (read, name) = read_client_hello(&mut io, head.to_vec()).await.unwrap();
        assert_eq!(name.as_deref(), Some("chatgpt.com"));
        assert_eq!(read, hello);
    }

    #[tokio::test]
    async fn what_is_not_a_client_hello_names_nothing() {
        let mut io = std::io::Cursor::new(b"GET / HTTP/1.1\r\n\r\n".to_vec());
        let (read, name) = read_client_hello(&mut io, vec![]).await.unwrap();
        assert_eq!(name, None);
        assert_eq!(read, b"GET /");

        let hello = client_hello("claude.ai");
        for cut in [6, 40, hello.len() - 5] {
            assert_eq!(server_name(&hello[5..cut]), None, "cut at {cut}");
        }
    }
}
