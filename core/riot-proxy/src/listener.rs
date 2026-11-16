//! The proxy's front door, on loopback. A connection opens with an HTTP `CONNECT`, from the
//! network extension (which relays the protected apps' flows and names their source) or from
//! anything that speaks to an HTTP proxy (`curl -x`, an app's `--proxy-server`):
//!
//! ```text
//! CONNECT 160.79.104.10:443 HTTP/1.1
//! X-Riot-Bundle-Id: com.anthropic.claudefordesktop
//! X-Riot-Uid: 501
//! ```
//!
//! The TLS ClientHello that follows names the host. A protected one is intercepted; any other
//! connection is relayed byte for byte to the address it asked for, still encrypted.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::{Flow, Inspector, Shared, mitm, sni};

const MAX_PREFACE: usize = 8 * 1024;
/// For the preface and the ClientHello: a client that opens a connection and says nothing.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) async fn run<I: Inspector>(shared: Arc<Shared<I>>, listener: TcpListener) {
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(shared, tcp).await {
                tracing::debug!(error = %e, "proxy connection ended");
            }
        });
    }
}

async fn connection<I: Inspector>(shared: Arc<Shared<I>>, mut tcp: TcpStream) -> std::io::Result<()> {
    tcp.set_nodelay(true)?;
    let hello = async {
        let mut preface = match read_preface(&mut tcp).await? {
            Ok(preface) => preface,
            Err(status) => {
                tcp.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
                return Ok(None);
            }
        };
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let (read, name) = sni::read_client_hello(&mut tcp, std::mem::take(&mut preface.rest)).await?;
        Ok::<_, std::io::Error>(Some((preface, read, name)))
    };
    let Some((preface, read, name)) = tokio::time::timeout(HELLO_TIMEOUT, hello).await?? else { return Ok(()) };

    if let Some(host) = name.clone() {
        let flow = Flow { host, port: preface.port, bundle_id: preface.bundle_id.clone(), uid: preface.uid, pid: preface.pid };
        if shared.inspector.rules(&flow).is_some() {
            shared.stats.intercepted.fetch_add(1, Relaxed);
            mitm::serve(shared, Arc::new(flow), Prefixed { prefix: read, at: 0, inner: tcp }).await;
            return Ok(());
        }
    }

    shared.stats.relayed.fetch_add(1, Relaxed);
    if shared.record {
        // Where the app's other connections go: a host that should have been protected shows here.
        tracing::info!(target: "riot_proxy::record", host = name.as_deref().unwrap_or("-"), port = preface.port, "relayed");
    }
    let connect = TcpStream::connect((preface.host.as_str(), preface.port));
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, connect).await??;
    upstream.set_nodelay(true)?;
    upstream.write_all(&read).await?;
    tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await?;
    Ok(())
}

struct Preface {
    host: String,
    port: u16,
    bundle_id: Option<String>,
    uid: Option<u32>,
    pid: Option<u32>,
    /// Bytes the client sent after the preface without waiting for the reply.
    rest: Vec<u8>,
}

/// Reads the `CONNECT` request. The inner error is the status line to refuse it with.
async fn read_preface(tcp: &mut TcpStream) -> std::io::Result<Result<Preface, &'static str>> {
    let mut buf = Vec::with_capacity(512);
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        if buf.len() > MAX_PREFACE {
            return Ok(Err("431 Request Header Fields Too Large"));
        }
        let mut chunk = [0u8; 1024];
        let read = tcp.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    };
    let rest = buf[end + 4..].to_vec();
    let Ok(head) = std::str::from_utf8(&buf[..end]) else { return Ok(Err("400 Bad Request")) };
    Ok(parse_preface(head, rest))
}

fn parse_preface(head: &str, rest: Vec<u8>) -> Result<Preface, &'static str> {
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(authority)) = (request.next(), request.next()) else { return Err("400 Bad Request") };
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err("405 Method Not Allowed"); // only tunnels: plain HTTP is not proxied
    }
    let (host, port) = authority.rsplit_once(':').ok_or("400 Bad Request")?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    let port = port.parse().map_err(|_| "400 Bad Request")?;
    if host.is_empty() {
        return Err("400 Bad Request");
    }
    let mut preface = Preface { host, port, bundle_id: None, uid: None, pid: None, rest };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "x-riot-bundle-id" if !value.is_empty() => preface.bundle_id = Some(value.to_owned()),
            "x-riot-uid" => preface.uid = value.parse().ok(),
            "x-riot-pid" => preface.pid = value.parse().ok(),
            _ => {}
        }
    }
    Ok(preface)
}

/// A stream that first yields bytes already read from it: the ClientHello, replayed to the TLS
/// acceptor.
struct Prefixed<T> {
    prefix: Vec<u8>,
    at: usize,
    inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let len = (self.prefix.len() - self.at).min(buf.remaining());
            buf.put_slice(&self.prefix[self.at..self.at + len]);
            self.at += len;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_destination_and_the_source() {
        let head = "CONNECT 160.79.104.10:443 HTTP/1.1\r\nHost: 160.79.104.10:443\r\n\
                    X-Riot-Bundle-Id: com.anthropic.claudefordesktop\r\nx-riot-uid: 501\r\nX-Riot-Pid: 4242";
        let p = parse_preface(head, vec![]).unwrap();
        assert_eq!((p.host.as_str(), p.port), ("160.79.104.10", 443));
        assert_eq!(p.bundle_id.as_deref(), Some("com.anthropic.claudefordesktop"));
        assert_eq!((p.uid, p.pid), (Some(501), Some(4242)));

        let p = parse_preface("CONNECT [2606:4700::1]:443 HTTP/1.1", vec![]).unwrap();
        assert_eq!((p.host.as_str(), p.port, p.bundle_id), ("2606:4700::1", 443, None));
    }

    #[test]
    fn refuses_what_is_not_a_tunnel() {
        assert_eq!(parse_preface("GET http://example.com/ HTTP/1.1", vec![]).err(), Some("405 Method Not Allowed"));
        assert_eq!(parse_preface("CONNECT example.com HTTP/1.1", vec![]).err(), Some("400 Bad Request"));
        assert_eq!(parse_preface("CONNECT example.com:https HTTP/1.1", vec![]).err(), Some("400 Bad Request"));
        assert_eq!(parse_preface("", vec![]).err(), Some("400 Bad Request"));
    }
}
