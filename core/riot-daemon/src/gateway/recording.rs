//! A stream that keeps what was read from it, so that bytes consumed to read a TLS ClientHello
//! (its server name decides the route) can be replayed when the connection is tunnelled instead.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct Recording<S> {
    inner: S,
    recorded: Option<Vec<u8>>,
}

impl<S> Recording<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, recorded: Some(vec![]) }
    }

    /// Stops recording; returns what was read so far.
    pub fn stop(&mut self) -> Vec<u8> {
        self.recorded.take().unwrap_or_default()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(recorded)) = (&polled, self.recorded.as_mut()) {
            recorded.extend_from_slice(&buf.filled()[before..]);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
