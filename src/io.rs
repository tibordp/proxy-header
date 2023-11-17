//! IO wrapper for proxied streams.
//!
//! PROXY protocol header is variable length so it is not possible to read a fixed number of bytes
//! directly from the stream and reading it byte-by-byte can be inefficient. [`ProxiedStream`] reads
//! enough bytes to parse the header and retains any extra bytes that may have been read.
//!
//! If the underlying stream is already buffered (i.e. [`std::io::BufRead`] or equivalent), it is
//! probably a better idea to just decode the header directly instead of using [`ProxiedStream`].
//!
//! The wrapper is usable both with standard ([`std::io::Read`]) and Tokio streams ([`tokio::io::AsyncRead`]).
//!
//! ## Example (Tokio)
//!
//! ```no_run
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use tokio::net::TcpListener;
//! use proxy_header::io::ProxiedStream;
//!
//! let listener = TcpListener::bind("[::]:1234").await?;
//!
//! loop {
//!     let (mut socket, _) = listener.accept().await?;
//!     tokio::spawn(async move {
//!         // Read the proxy header first
//!         let mut socket = ProxiedStream::create_from_tokio(socket, Default::default())
//!             .await
//!             .expect("failed to create proxied stream");
//!
//!         // We can now inspect the address
//!         println!("proxy header: {:?}", socket.proxy_header());
//!
//!         /// Then process the protocol
//!         let mut buf = vec![0; 1024];
//!         loop {
//!             let n = socket.read(&mut buf).await.unwrap();
//!             if n == 0 {
//!                 return;
//!             }
//!             socket.write_all(&buf[0..n]).await.unwrap();
//!         }
//!     });
//! }
//! # }
//! ```
use std::{
    io::{self, BufRead, Read, Write},
    mem::MaybeUninit,
};

#[cfg(any(unix, target_os = "wasi"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

#[cfg(feature = "tokio")]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "tokio")]
use pin_project_lite::pin_project;

#[cfg(feature = "tokio")]
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{Error, ParseConfig, ProxyHeader};

#[cfg(all(feature = "tokio", not(doc)))]
pin_project! {
    #[derive(Debug)]
    pub struct ProxiedStream<IO> {
        #[pin]
        io: IO,
        remaining: Vec<u8>,
        header: ProxyHeader<'static>,
    }
}

/// Wrapper around a stream that starts with a proxy header.
///
/// See [module level documentation](`crate::io`)
#[cfg(any(doc, not(feature = "tokio")))]
#[derive(Debug)]
pub struct ProxiedStream<IO> {
    io: IO,
    remaining: Vec<u8>,
    header: ProxyHeader<'static>,
}

impl<IO> ProxiedStream<IO> {
    /// Create a new proxied stream from an stream that does not have a proxy header.
    ///
    /// This is useful if you want to use the same stream type for proxied and unproxied
    /// connections.
    pub fn unproxied(io: IO) -> Self {
        Self {
            io,
            remaining: vec![],
            header: Default::default(),
        }
    }

    /// Get the proxy header.
    pub fn proxy_header(&self) -> &ProxyHeader {
        &self.header
    }

    /// Gets a reference to the underlying stream.
    pub fn get_ref(&self) -> &IO {
        &self.io
    }

    /// Gets a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    /// Gets a pinned mutable reference to the underlying stream.
    #[cfg(feature = "tokio")]
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut IO> {
        self.project().io
    }

    /// Consumes this wrapper, returning the underlying stream.
    pub fn into_inner(self) -> IO {
        self.io
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl<IO> ProxiedStream<IO>
where
    IO: AsyncRead + Unpin,
{
    /// Reads the proxy header from an [`tokio::io::AsyncRead`] stream and returns a new [`ProxiedStream`].
    ///
    /// This method will read from the stream until a proxy header is found, or the
    /// stream is closed. If the stream is closed before a proxy header is found,
    /// this method will return an [`io::Error`] with [`io::ErrorKind::UnexpectedEof`].
    ///
    /// If the stream contains invalid data, this method will return an [`io::Error`]
    /// with [`io::ErrorKind::InvalidData`]. In case of an error, the stream is dropped,
    /// and any remaining bytes are discarded (which usually means the connection
    /// is closed).
    pub async fn create_from_tokio(mut io: IO, config: ParseConfig) -> io::Result<Self> {
        use tokio::io::AsyncReadExt;

        // 256 bytes should be enough for the longest realistic header with
        // all extensions. If not, we'll just reallocate. theoretical maximum
        // is 12 + 4 + 65535 = 65551 bytes, though that would be very silly.
        //
        // Maybe we should just error out if we get more than 512 bytes?
        let mut bytes = Vec::with_capacity(256);

        loop {
            let bytes_read = io.read_buf(&mut bytes).await?;
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "end of stream",
                ));
            }

            match ProxyHeader::parse(&bytes, config) {
                Ok((ret, consumed)) => {
                    let ret = ret.into_owned();
                    bytes.drain(..consumed);

                    return Ok(Self {
                        io,
                        remaining: bytes,
                        header: ret,
                    });
                }
                Err(Error::BufferTooShort) => continue,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid proxy header",
                    ))
                }
            }
        }
    }
}

impl<IO> ProxiedStream<IO>
where
    IO: Read,
{
    /// Reads the proxy header from a [`Read`] stream and returns a new `ProxiedStream`.
    ///
    /// Other than the fact that this method is synchronous, it is identical to [`create_from_tokio`](Self::create_from_tokio).
    pub fn create_from_std(mut io: IO, config: ParseConfig) -> io::Result<Self> {
        let mut bytes = Vec::with_capacity(256);

        loop {
            if bytes.capacity() == bytes.len() {
                bytes.reserve(32);
            }

            // TODO: Get rid of this once read-buf is stabilized
            // (https://github.com/rust-lang/rust/issues/78485)

            let buf = bytes.spare_capacity_mut();
            buf.fill(MaybeUninit::new(0));

            // SAFETY: We just initialized the whole spare capacity
            let buf: &mut [u8] = unsafe { std::mem::transmute(buf) };

            let bytes_read = io.read(buf)?;
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "end of stream",
                ));
            }

            // SAFETY: The bytes are initialized even if the reader lies about how many
            // bytes were read.
            unsafe {
                assert!(bytes_read <= buf.len());
                bytes.set_len(bytes.len() + bytes_read);
            }

            match ProxyHeader::parse(&bytes, config) {
                Ok((ret, consumed)) => {
                    let ret = ret.into_owned();
                    bytes.drain(..consumed);

                    return Ok(Self {
                        io,
                        remaining: bytes,
                        header: ret,
                    });
                }
                Err(Error::BufferTooShort) => continue,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid proxy header",
                    ))
                }
            }
        }
    }
}

impl<IO> Read for ProxiedStream<IO>
where
    IO: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.remaining.is_empty() {
            let len = std::cmp::min(self.remaining.len(), buf.len());

            buf[..len].copy_from_slice(&self.remaining[..len]);
            self.remaining.drain(..len);

            return Ok(len);
        }

        self.io.read(buf)
    }
}

impl<IO> BufRead for ProxiedStream<IO>
where
    IO: BufRead,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if !self.remaining.is_empty() {
            return Ok(&self.remaining);
        }
        self.io.fill_buf()
    }

    fn consume(&mut self, mut amt: usize) {
        if !self.remaining.is_empty() {
            let len = std::cmp::min(self.remaining.len(), amt);
            self.remaining.drain(..len);
            amt -= len;
        }
        self.io.consume(amt);
    }
}

impl<IO> Write for ProxiedStream<IO>
where
    IO: Write,
{
    #[inline]
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.io.write_vectored(bufs)
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.io.write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
        self.io.write_fmt(fmt)
    }

    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl<IO> AsyncBufRead for ProxiedStream<IO>
where
    IO: AsyncBufRead,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.project();

        if !me.remaining.is_empty() {
            return Poll::Ready(Ok(&me.remaining[..]));
        }

        me.io.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();

        if !me.remaining.is_empty() {
            let len = std::cmp::min(me.remaining.len(), amt);
            me.remaining.drain(..len);
        }

        me.io.consume(amt);
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl<IO> AsyncRead for ProxiedStream<IO>
where
    IO: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();

        if !me.remaining.is_empty() {
            let len = std::cmp::min(me.remaining.len(), buf.remaining());

            buf.put_slice(&me.remaining[..len]);
            me.remaining.drain(..len);

            return Poll::Ready(Ok(()));
        }

        me.io.poll_read(cx, buf)
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl<IO> AsyncWrite for ProxiedStream<IO>
where
    IO: AsyncWrite,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().io.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().io.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

#[cfg(any(unix, target_os = "wasi"))]
#[cfg_attr(docsrs, doc(cfg(any(unix, target_os = "wasi"))))]
impl<IO> AsRawFd for ProxiedStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

#[cfg(any(unix, target_os = "wasi"))]
#[cfg_attr(docsrs, doc(cfg(any(unix, target_os = "wasi"))))]
impl<IO> AsFd for ProxiedStream<IO>
where
    IO: AsFd,
{
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.io.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Protocol, ProxiedAddress, ProxyHeader};
    use std::{
        io::Cursor,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    };

    #[test]
    fn test_sync() {
        let mut buf = [0; 1024];

        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5678)),
        });

        let written_len = header.encode_to_slice_v2(&mut buf).unwrap();
        buf[written_len..].fill(255);

        let mut stream = Cursor::new(&buf);

        let mut proxied = ProxiedStream::create_from_std(&mut stream, Default::default()).unwrap();
        assert_eq!(proxied.proxy_header(), &header);

        let mut buf = Vec::new();
        proxied.read_to_end(&mut buf).unwrap();

        assert_eq!(buf.len(), 1024 - written_len);
        assert!(buf.into_iter().all(|b| b == 255));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn test_tokio() {
        use tokio::io::AsyncReadExt;

        let mut buf = [0; 1024];

        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5678)),
        });

        let written_len = header.encode_to_slice_v2(&mut buf).unwrap();
        buf[written_len..].fill(255);

        let mut stream = Cursor::new(&buf);

        let mut proxied = ProxiedStream::create_from_tokio(&mut stream, Default::default())
            .await
            .unwrap();
        assert_eq!(proxied.proxy_header(), &header);

        let mut buf = Vec::new();
        AsyncReadExt::read_to_end(&mut proxied, &mut buf)
            .await
            .unwrap();

        assert_eq!(buf.len(), 1024 - written_len);
        assert!(buf.into_iter().all(|b| b == 255));
    }
}
