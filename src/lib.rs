//! PROXY protocol decoder and encoder
//!
//! This crate provides a decoder and encoder for the
//! [PROXY protocol](https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt),
//! which is used to preserve original client connection information when proxying TCP
//! connections for protocols that do not support this higher up in the stack.
//!
//! The PROXY protocol is supported by many load balancers and proxies, including HAProxy,
//! Amazon ELB, Amazon ALB, and others.
//!
//! This crate implements the entire specification, except parsing the `AF_UNIX` address
//! type (the header is validated / parsed, but the address is not decoded or exposed in
//! the API).
//!
//! # Usage
//!
//! ## Decoding
//!
//! To decode a PROXY protocol header from an existing buffer, use [`ProxyHeader::parse`]:
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use proxy_header::{ProxyHeader, ParseConfig};
//!
//! let buf = b"PROXY TCP6 2001:db8:1::1 2001:db8:2::1 52953 25\r\nHELO example.com\r\n";
//!
//! let (header, len) = ProxyHeader::parse(buf, ParseConfig::default())?;
//! match header.proxied_address() {
//!    Some(addr) => {
//!       println!("Proxied connection from {} to {}", addr.source, addr.destination);
//!    }
//!    None => {
//!       println!("Local connection (e.g. healthcheck)");
//!   }
//! }
//!
//! println!("Client sent: {:?}", &buf[len..]);
//! # Ok(())
//! # }
//! ```
//!
//! In addition to the address information, the PROXY protocol version 2 header can contain
//! additional information in the form of TLV (type-length-value) fields. These can be accessed
//! through the [`ProxyHeader::tlvs`] iterator or through convenience accessors such as [`ProxyHeader::authority`].
//!
//! See [`Tlv`] for more information on the different types of TLV fields.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # use proxy_header::{ProxyHeader, ParseConfig};
//! # let buf = b"PROXY TCP4 10.0.0.1 10.0.0.2 52953 25\r\nHELO example.com\r\n";
//! # let (header, _) = ProxyHeader::parse(buf, ParseConfig::default()).unwrap();
//! use proxy_header::Tlv;
//!
//! for tlv in header.tlvs() {
//!     match tlv? {  // TLV can be malformed
//!         Tlv::UniqueId(v) => {
//!             println!("Unique connection ID: {:?}", v);
//!         }
//!         Tlv::Authority(v) => {
//!             println!("Authority string (SNI): {:?}", v);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! See also [`io`] module for a stream wrapper that can automatically parse PROXY protocol.
//!
//! ## Encoding
//!
//! To encode a PROXY protocol header, use [`ProxyHeader::encode_v1`] for version 1 headers and
//! [`ProxyHeader::encode_v2`] for version 2 headers.
//!
//! ```
//! use proxy_header::{ProxyHeader, ProxiedAddress, Protocol};
//!
//! let addrs = ProxiedAddress::stream(
//!    "[2001:db8::1:1]:51234".parse().unwrap(),
//!    "[2001:db8::2:1]:443".parse().unwrap()
//! );
//! let header = ProxyHeader::with_address(addrs);
//!
//! let mut buf = [0u8; 1024];
//! let len = header.encode_to_slice_v2(&mut buf).unwrap();
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod util;
mod v1;
mod v2;

pub mod io;

use crate::util::{tlv, tlv_borrowed};
use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;

/// Protocol type
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Protocol {
    /// Stream protocol (TCP)
    Stream,
    /// Datagram protocol (UDP)
    Datagram,
}

/// Address information from a PROXY protocol header
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ProxiedAddress {
    /// Protocol type (TCP or UDP)
    pub protocol: Protocol,
    /// Source address (this is the address of the actual client)
    pub source: SocketAddr,
    /// Destination address (this is the address of the proxy)
    pub destination: SocketAddr,
}

impl ProxiedAddress {
    pub fn stream(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            protocol: Protocol::Stream,
            source,
            destination,
        }
    }

    pub fn datagram(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            protocol: Protocol::Datagram,
            source,
            destination,
        }
    }
}

/// Iterator over PROXY protocol TLV (type-length-value) fields
pub struct Tlvs<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = Result<Tlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }

        let kind = self.buf[0];
        match self
            .buf
            .get(1..3)
            .map(|s| u16::from_be_bytes(s.try_into().unwrap()) as usize)
        {
            Some(u) if u + 3 <= self.buf.len() => {
                let (ret, new) = self.buf.split_at(3 + u);
                self.buf = new;

                Some(Tlv::decode(kind, &ret[3..]))
            }
            _ => {
                // Malformed TLV, we cannot continue
                self.buf = &[];
                Some(Err(Error::Invalid))
            }
        }
    }
}

/// SSL information from a PROXY protocol header
#[derive(PartialEq, Eq, Clone)]
pub struct SslInfo<'a>(u8, u32, Cow<'a, [u8]>);

impl<'a> SslInfo<'a> {
    /// Create a new SSL information struct
    pub fn new(
        client_ssl: bool,
        client_cert_conn: bool,
        client_cert_sess: bool,
        verify: u32,
    ) -> Self {
        Self(
            (client_ssl as u8) | (client_cert_conn as u8) << 1 | (client_cert_sess as u8) << 2,
            verify,
            Default::default(),
        )
    }

    /// Client connected over SSL/TLS
    ///
    /// The PP2_CLIENT_SSL flag indicates that the client connected over SSL/TLS. When
    /// this field is present, the US-ASCII string representation of the TLS version is
    /// appended at the end of the field in the TLV format using the type
    /// PP2_SUBTYPE_SSL_VERSION.
    pub fn client_ssl(&self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Client certificate presented in the connection
    ///
    /// PP2_CLIENT_CERT_CONN indicates that the client provided a certificate over the
    /// current connection.
    pub fn client_cert_conn(&self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Client certificate presented in the session
    ///
    /// PP2_CLIENT_CERT_SESS indicates that the client provided a
    /// certificate at least once over the TLS session this connection belongs to.
    pub fn client_cert_sess(&self) -> bool {
        self.0 & 0x04 != 0
    }

    /// Whether the certificate was verified
    ///
    /// The verify field will be zero if the client presented a certificate
    /// and it was successfully verified, and non-zero otherwise.
    pub fn verify(&self) -> u32 {
        self.1
    }

    /// Iterator over all TLV (type-length-value) fields
    pub fn tlvs(&self) -> Tlvs<'_> {
        Tlvs { buf: &self.2 }
    }

    // Convenience accessors for common TLVs

    /// SSL version
    ///
    /// See [`Tlv::SslVersion`] for more information.
    pub fn version(&self) -> Option<&str> {
        tlv_borrowed!(self, SslVersion)
    }

    /// SSL CN
    ///
    /// See [`Tlv::SslCn`] for more information.
    pub fn cn(&self) -> Option<&str> {
        tlv_borrowed!(self, SslCn)
    }

    /// SSL cipher
    ///
    /// See [`Tlv::SslCipher`] for more information.
    pub fn cipher(&self) -> Option<&str> {
        tlv_borrowed!(self, SslCipher)
    }

    /// SSL signature algorithm
    ///
    /// See [`Tlv::SslSigAlg`] for more information.
    pub fn sig_alg(&self) -> Option<&str> {
        tlv_borrowed!(self, SslSigAlg)
    }

    /// SSL key algorithm
    ///
    /// See [`Tlv::SslKeyAlg`] for more information.
    pub fn key_alg(&self) -> Option<&str> {
        tlv_borrowed!(self, SslKeyAlg)
    }

    /// Returns an owned version of this struct
    pub fn into_owned(self) -> SslInfo<'static> {
        SslInfo(self.0, self.1, Cow::Owned(self.2.into_owned()))
    }

    /// Appends an additional sub-TLV field
    ///
    /// See [`ProxyHeader::append_tlv`] for more information.
    pub fn append_tlv(&mut self, tlv: Tlv<'_>) {
        tlv.encode(self.2.to_mut());
    }
}

impl fmt::Debug for SslInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ssl")
            .field("verify", &self.verify())
            .field("client_ssl", &self.client_ssl())
            .field("client_cert_conn", &self.client_cert_conn())
            .field("client_cert_sess", &self.client_cert_sess())
            .field("fields", &self.tlvs().collect::<Vec<_>>())
            .finish()
    }
}

/// Typed TLV (type-length-value) field
///
/// Represents the currently known types of TLV fields from the PROXY protocol specification.
/// Non-recognized TLV fields are represented as [`Tlv::Custom`].
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Tlv<'a> {
    /// Application-Layer Protocol Negotiation (ALPN). It is a byte sequence defining
    /// the upper layer protocol in use over the connection. The most common use case
    /// will be to pass the exact copy of the ALPN extension of the Transport Layer
    /// Security (TLS) protocol as defined by RFC7301.
    Alpn(Cow<'a, [u8]>),

    /// Contains the host name value passed by the client, as an UTF8-encoded string.
    /// In case of TLS being used on the client connection, this is the exact copy of
    /// the "server_name" extension as defined by RFC3546, section 3.1, often
    /// referred to as "SNI". There are probably other situations where an authority
    /// can be mentioned on a connection without TLS being involved at all.
    Authority(Cow<'a, str>),

    /// The value of the type PP2_TYPE_CRC32C is a 32-bit number storing the CRC32c
    /// checksum of the PROXY protocol header.
    ///
    /// When the checksum is supported by the sender after constructing the header
    /// the sender MUST:
    ///
    /// - initialize the checksum field to '0's.
    ///
    /// - calculate the CRC32c checksum of the PROXY header as described in RFC4960,
    /// Appendix B.
    ///
    /// - put the resultant value into the checksum field, and leave the rest of
    /// the bits unchanged.
    ///
    /// If the checksum is provided as part of the PROXY header and the checksum
    /// functionality is supported by the receiver, the receiver MUST:
    ///
    /// - store the received CRC32c checksum value aside.
    ///
    /// - replace the 32 bits of the checksum field in the received PROXY header with
    /// all '0's and calculate a CRC32c checksum value of the whole PROXY header.
    ///
    /// - verify that the calculated CRC32c checksum is the same as the received
    /// CRC32c checksum. If it is not, the receiver MUST treat the TCP connection
    /// providing the header as invalid.
    ///
    /// The default procedure for handling an invalid TCP connection is to abort it.
    Crc32c(u32),

    /// The TLV of this type should be ignored when parsed. The value is zero or more
    /// bytes. Can be used for data padding or alignment. Note that it can be used
    /// to align only by 3 or more bytes because a TLV can not be smaller than that.
    Noop(usize),

    /// The value of the type PP2_TYPE_UNIQUE_ID is an opaque byte sequence of up to
    /// 128 bytes generated by the upstream proxy that uniquely identifies the
    /// connection.
    ///
    /// The unique ID can be used to easily correlate connections across multiple
    /// layers of proxies, without needing to look up IP addresses and port numbers.
    UniqueId(Cow<'a, [u8]>),

    /// SSL (TLS) information
    ///
    /// See [`SslInfo`] for more information.
    Ssl(SslInfo<'a>),

    /// The type PP2_TYPE_NETNS defines the value as the US-ASCII string representation
    /// of the namespace's name.
    Netns(Cow<'a, str>),

    // These can only appear as a sub-TLV of SslInfo
    /// SSL/TLS version
    SslVersion(Cow<'a, str>),

    /// In all cases, the string representation (in UTF8) of the Common Name field
    /// (OID: 2.5.4.3) of the client certificate's Distinguished Name, is appended
    /// using the TLV format and the type PP2_SUBTYPE_SSL_CN. E.g. "example.com".
    SslCn(Cow<'a, str>),

    /// The second level TLV PP2_SUBTYPE_SSL_CIPHER provides the US-ASCII string name
    /// of the used cipher, for example "ECDHE-RSA-AES128-GCM-SHA256".
    SslCipher(Cow<'a, str>),

    /// The second level TLV PP2_SUBTYPE_SSL_SIG_ALG provides the US-ASCII string name
    /// of the algorithm used to sign the certificate presented by the frontend when
    /// the incoming connection was made over an SSL/TLS transport layer, for example
    /// "SHA256".
    SslSigAlg(Cow<'a, str>),

    /// The second level TLV PP2_SUBTYPE_SSL_KEY_ALG provides the US-ASCII string name
    /// of the algorithm used to generate the key of the certificate presented by the
    /// frontend when the incoming connection was made over an SSL/TLS transport layer,
    /// for example "RSA2048".
    SslKeyAlg(Cow<'a, str>),

    /// Unrecognized or custom TLV field
    Custom(u8, Cow<'a, [u8]>),
}

impl<'a> Tlv<'a> {
    /// Decode a TLV field from the given buffer
    ///
    /// Returns an error if the field is malformed.
    pub fn decode(kind: u8, data: &'a [u8]) -> Result<Tlv<'a>, Error> {
        use std::str::from_utf8;
        use Tlv::*;

        match kind {
            0x01 => Ok(Alpn(data.into())),
            0x02 => Ok(Authority(
                from_utf8(data).map_err(|_| Error::Invalid)?.into(),
            )),
            0x03 => Ok(Crc32c(u32::from_be_bytes(
                data.try_into().map_err(|_| Error::Invalid)?,
            ))),
            0x04 => Ok(Noop(data.len())),
            0x05 => Ok(UniqueId(data.into())),
            0x20 => Ok(Ssl(SslInfo(
                *data.first().ok_or(Error::Invalid)?,
                u32::from_be_bytes(
                    data.get(1..5)
                        .ok_or(Error::Invalid)?
                        .try_into()
                        .map_err(|_| Error::Invalid)?,
                ),
                data.get(5..).ok_or(Error::Invalid)?.into(),
            ))),
            0x21 => Ok(SslVersion(
                from_utf8(data).map_err(|_| Error::Invalid)?.into(),
            )),
            0x22 => Ok(SslCn(from_utf8(data).map_err(|_| Error::Invalid)?.into())),
            0x23 => Ok(SslCipher(
                from_utf8(data).map_err(|_| Error::Invalid)?.into(),
            )),
            0x24 => Ok(SslSigAlg(
                from_utf8(data).map_err(|_| Error::Invalid)?.into(),
            )),
            0x25 => Ok(SslKeyAlg(
                from_utf8(data).map_err(|_| Error::Invalid)?.into(),
            )),
            0x30 => Ok(Netns(from_utf8(data).map_err(|_| Error::Invalid)?.into())),
            a => Ok(Custom(a, data.into())),
        }
    }

    /// Returns the raw kind of this TLV field
    pub fn kind(&self) -> u8 {
        match self {
            Tlv::Alpn(_) => 0x01,
            Tlv::Authority(_) => 0x02,
            Tlv::Crc32c(_) => 0x03,
            Tlv::Noop(_) => 0x04,
            Tlv::UniqueId(_) => 0x05,
            Tlv::Ssl(_) => 0x20,
            Tlv::Netns(_) => 0x30,
            Tlv::SslVersion(_) => 0x21,
            Tlv::SslCn(_) => 0x22,
            Tlv::SslCipher(_) => 0x23,
            Tlv::SslSigAlg(_) => 0x24,
            Tlv::SslKeyAlg(_) => 0x25,
            Tlv::Custom(a, _) => *a,
        }
    }

    /// Encode this TLV field into the given buffer
    ///
    /// # Panics
    /// Panics if the field is too long for its length to fit in a [`u16`].
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let initial = buf.len();

        buf.extend_from_slice(&[self.kind(), 0, 0]);
        match self {
            Tlv::Alpn(v) => buf.extend_from_slice(v),
            Tlv::Authority(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::Crc32c(v) => buf.extend_from_slice(&v.to_be_bytes()),
            Tlv::Noop(len) => {
                buf.resize(buf.len() + len, 0);
            }
            Tlv::UniqueId(v) => buf.extend_from_slice(v),
            Tlv::Ssl(v) => {
                buf.push(v.0);
                buf.extend_from_slice(&v.1.to_be_bytes());
                buf.extend_from_slice(&v.2);
            }
            Tlv::Netns(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::SslVersion(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::SslCn(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::SslCipher(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::SslSigAlg(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::SslKeyAlg(v) => buf.extend_from_slice(v.as_bytes()),
            Tlv::Custom(_, v) => buf.extend_from_slice(v),
        }

        let len = buf.len() - initial - 3;
        if len > u16::MAX as usize {
            panic!("TLV field too long");
        }

        buf[initial + 1] = ((len >> 8) & 0xff) as u8;
        buf[initial + 2] = (len & 0xff) as u8;
    }

    /// Returns an owned version of this struct
    pub fn into_owned(self) -> Tlv<'static> {
        match self {
            Tlv::Alpn(v) => Tlv::Alpn(Cow::Owned(v.into_owned())),
            Tlv::Authority(v) => Tlv::Authority(Cow::Owned(v.into_owned())),
            Tlv::Crc32c(v) => Tlv::Crc32c(v),
            Tlv::Noop(v) => Tlv::Noop(v),
            Tlv::UniqueId(v) => Tlv::UniqueId(Cow::Owned(v.into_owned())),
            Tlv::Ssl(v) => Tlv::Ssl(v.into_owned()),
            Tlv::Netns(v) => Tlv::Netns(Cow::Owned(v.into_owned())),
            Tlv::SslVersion(v) => Tlv::SslVersion(Cow::Owned(v.into_owned())),
            Tlv::SslCn(v) => Tlv::SslCn(Cow::Owned(v.into_owned())),
            Tlv::SslCipher(v) => Tlv::SslCipher(Cow::Owned(v.into_owned())),
            Tlv::SslSigAlg(v) => Tlv::SslSigAlg(Cow::Owned(v.into_owned())),
            Tlv::SslKeyAlg(v) => Tlv::SslKeyAlg(Cow::Owned(v.into_owned())),
            Tlv::Custom(a, v) => Tlv::Custom(a, Cow::Owned(v.into_owned())),
        }
    }
}

/// Configuration for parsing PROXY protocol headers
#[derive(Debug, Copy, Clone)]
pub struct ParseConfig {
    /// Whether to include TLV (type-length-value) fields in the parsed header
    ///
    /// Even though the TLV section is parsed lazily when accessed, this can save
    /// an allocation.
    pub include_tlvs: bool,

    /// Whether to allow V1 headers
    pub allow_v1: bool,

    /// Whether to allow V2 headers
    pub allow_v2: bool,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            include_tlvs: true,
            allow_v1: true,
            allow_v2: true,
        }
    }
}

/// A PROXY protocol header
#[derive(Default, PartialEq, Eq, Clone)]
pub struct ProxyHeader<'a>(Option<ProxiedAddress>, Cow<'a, [u8]>);

impl<'a> ProxyHeader<'a> {
    /// Create a new PROXY protocol header (local mode)
    pub fn with_local() -> Self {
        Default::default()
    }

    /// Create a new PROXY protocol header (proxied mode)
    pub fn with_address(addr: ProxiedAddress) -> Self {
        Self(Some(addr), Cow::Owned(Vec::new()))
    }

    /// Create a new PROXY protocol header with the given TLV fields
    ///
    /// ```
    /// use proxy_header::{ProxyHeader, ProxiedAddress, Tlv, Protocol, SslInfo};
    ///
    /// let addrs = ProxiedAddress::stream(
    ///     "[2001:db8::1:1]:51234".parse().unwrap(),
    ///     "[2001:db8::2:1]:443".parse().unwrap()
    /// );
    /// let header = ProxyHeader::with_tlvs(
    ///    Some(addrs), [
    ///         Tlv::Authority("example.com".into()),
    ///         Tlv::Ssl(SslInfo::new(true, false, false, 0)),
    ///      ]
    /// );
    ///
    /// println!("{:?}", header);
    /// ```
    pub fn with_tlvs<'b>(
        addr: Option<ProxiedAddress>,
        tlvs: impl IntoIterator<Item = Tlv<'b>>,
    ) -> Self {
        let mut buf = Vec::with_capacity(64);
        for tlv in tlvs {
            tlv.encode(&mut buf);
        }

        Self(addr, Cow::Owned(buf))
    }

    /// Attempt to parse a PROXY protocol header from the given buffer
    ///
    /// Returns the parsed header and the number of bytes consumed from the buffer. If the header
    /// is incomplete, returns [`Error::BufferTooShort`] so more data can be read from the socket.
    ///
    /// If the header is malformed or unsupported, returns [`Error::Invalid`].
    ///
    /// This function will borrow the buffer for the lifetime of the returned header. If
    /// you need to keep the header around for longer than the buffer, use [`ProxyHeader::into_owned`].
    pub fn parse(buf: &'a [u8], config: ParseConfig) -> Result<(Self, usize), Error> {
        match buf.first() {
            Some(b'P') if config.allow_v1 => v1::decode(buf),
            Some(b'\r') if config.allow_v2 => v2::decode(buf, config),
            None => Err(Error::BufferTooShort),
            _ => Err(Error::Invalid),
        }
    }

    /// Proxied address information
    ///
    /// If `None`, this indicates so-called "local" mode, where the connection is not proxied.
    /// This is usually the case when the connection is initiated by the proxy itself, e.g. for
    /// health checks.
    pub fn proxied_address(&self) -> Option<&ProxiedAddress> {
        self.0.as_ref()
    }

    /// Iterator that yields all extension TLV (type-length-value) fields present in the header
    ///
    /// See [`Tlv`] for more information on the different types of TLV fields.
    pub fn tlvs(&self) -> Tlvs<'_> {
        Tlvs { buf: &self.1 }
    }

    // Convenience accessors for common fields

    /// Raw ALPN extension data
    ///
    /// See [`Tlv::Alpn`] for more information.
    pub fn alpn(&self) -> Option<&[u8]> {
        tlv_borrowed!(self, Alpn)
    }

    /// Authority - typically the hostname of the client (SNI)
    ///
    /// See [`Tlv::Authority`] for more information.
    pub fn authority(&self) -> Option<&str> {
        tlv_borrowed!(self, Authority)
    }

    /// CRC32c checksum of the address information
    ///
    /// See [`Tlv::Crc32c`] for more information.
    pub fn crc32c(&self) -> Option<u32> {
        tlv!(self, Crc32c)
    }

    /// Unique ID of the connection
    ///
    /// See [`Tlv::UniqueId`] for more information.
    pub fn unique_id(&self) -> Option<&[u8]> {
        tlv_borrowed!(self, UniqueId)
    }

    /// SSL information
    ///
    /// See [`Tlv::Ssl`] for more information.
    pub fn ssl(&self) -> Option<SslInfo<'_>> {
        tlv!(self, Ssl)
    }

    /// Network namespace
    ///
    /// See [`Tlv::Netns`] for more information.
    pub fn netns(&self) -> Option<&str> {
        tlv_borrowed!(self, Netns)
    }

    /// Returns an owned version of this struct
    pub fn into_owned(self) -> ProxyHeader<'static> {
        ProxyHeader(self.0, Cow::Owned(self.1.into_owned()))
    }

    /// Appends an additional TLV field
    pub fn append_tlv(&mut self, tlv: Tlv<'_>) {
        tlv.encode(self.1.to_mut());
    }

    /// Encode this PROXY protocol header into a [`Vec`] in version 1 format.
    ///
    /// Returns [`Error::V1UnsupportedTlv`] if the header contains any TLV fields and
    /// [`Error::V1UnsupportedProtocol`] if the header contains a non-TCP protocol, as
    /// version 1 PROXY protocol does not support either of these.
    pub fn encode_v1(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        v1::encode(self, buf)
    }

    /// Encode this PROXY protocol header into a [`Vec`] in version 2 format.
    pub fn encode_v2(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        v2::encode(self, buf)
    }

    /// Encode this PROXY protocol header into an existing buffer in version 1 format.
    ///
    /// If the buffer is too small to contain the entire header, returns [`Error::BufferTooShort`].
    ///
    /// See [`ProxyHeader::encode_v1`] for more information.
    pub fn encode_to_slice_v1(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut cursor = std::io::Cursor::new(buf);
        v1::encode(self, &mut cursor)?;

        Ok(cursor.position() as usize)
    }

    /// Encode this PROXY protocol header into an existing buffer in version 2 format.
    ///
    /// If the buffer is too small to contain the entire header, returns [`Error::BufferTooShort`].
    ///
    /// See [`ProxyHeader::encode_v2`] for more information.
    pub fn encode_to_slice_v2(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut cursor = std::io::Cursor::new(buf);
        v2::encode(self, &mut cursor)?;

        Ok(cursor.position() as usize)
    }
}

impl fmt::Debug for ProxyHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyHeader")
            .field("address_info", &self.proxied_address())
            .field("fields", &self.tlvs().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The buffer is too short to contain a complete PROXY protocol header
    BufferTooShort,
    /// The PROXY protocol header is malformed
    Invalid,
    /// The source and destination address families do not match
    AddressFamilyMismatch,
    /// The total size of the PROXY protocol header would exceed the maximum allowed size
    HeaderTooBig,
    /// The PROXY protocol header contains a TLV field, which is not supported in version 1
    V1UnsupportedTlv,
    /// The PROXY protocol header contains a non-TCP protocol, which is not supported in version 1
    V1UnsupportedProtocol,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            BufferTooShort => write!(f, "buffer too short"),
            Invalid => write!(f, "invalid PROXY header"),
            AddressFamilyMismatch => {
                write!(f, "source and destination address families do not match")
            }
            HeaderTooBig => write!(f, "PROXY header too big"),
            V1UnsupportedTlv => write!(f, "TLV fields are not supported in v1 header"),
            V1UnsupportedProtocol => {
                write!(f, "protocols other than TCP are not supported in v1 header")
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    const V1_UNKNOWN: &[u8] = b"PROXY UNKNOWN\r\n";

    const V1_TCPV4: &[u8] = b"PROXY TCP4 127.0.0.1 192.168.0.1 12345 443\r\n";
    const V1_TCPV6: &[u8] = b"PROXY TCP6 2001:db8::1 ::1 12345 443\r\n";

    const V2_LOCAL: &[u8] =
        b"\r\n\r\n\0\r\nQUIT\n \0\0\x0f\x03\0\x04\x88\x9d\xa1\xdf \0\x05\0\0\0\0\0";

    const V2_TCPV4: &[u8] = &[
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 12, 127, 0, 0, 1, 192, 168, 0, 1,
        48, 57, 1, 187,
    ];
    const V2_TCPV6: &[u8] = &[
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 33, 0, 36, 32, 1, 13, 184, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 48, 57, 1, 187,
    ];
    const V2_TCPV4_TLV: &[u8] = &[
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 104, 127, 0, 0, 1, 192, 168, 0,
        1, 48, 57, 1, 187, 3, 0, 4, 211, 153, 216, 216, 5, 0, 4, 49, 50, 51, 52, 32, 0, 75, 7, 0,
        0, 0, 0, 33, 0, 7, 84, 76, 83, 118, 49, 46, 51, 34, 0, 9, 108, 111, 99, 97, 108, 104, 111,
        115, 116, 37, 0, 7, 82, 83, 65, 52, 48, 57, 54, 36, 0, 10, 82, 83, 65, 45, 83, 72, 65, 50,
        53, 54, 35, 0, 22, 84, 76, 83, 95, 65, 69, 83, 95, 50, 53, 54, 95, 71, 67, 77, 95, 83, 72,
        65, 51, 56, 52,
    ];

    #[test]
    fn test_parse_proxy_header_too_short() {
        for case in [
            V1_TCPV4,
            V1_TCPV6,
            V1_UNKNOWN,
            V2_TCPV4,
            V2_TCPV6,
            V2_TCPV4_TLV,
            V2_LOCAL,
        ]
        .iter()
        {
            for i in 0..case.len() {
                assert!(matches!(
                    ProxyHeader::parse(&case[..i], Default::default()),
                    Err(Error::BufferTooShort)
                ));
            }

            assert!(matches!(
                ProxyHeader::parse(case, Default::default()),
                Ok(_)
            ));
        }
    }

    #[test]
    fn test_parse_proxy_header_v1_unterminated() {
        let line = b"PROXY TCP4 THISISSTORYALLABOUTHOWMYLIFEGOTFLIPPEDTURNEDUPSIDEDOWNANDIDLIKETOTAKEAMINUTEJUSTSITRIGHTTHEREANDILLTELLYOUHOWIGOTTHEPRINCEOFAIR\r\n";
        assert!(matches!(
            ProxyHeader::parse(line, Default::default()),
            Err(Error::Invalid)
        ));
    }

    #[test]
    fn test_parse_proxy_header_v1() {
        let (res, consumed) = ProxyHeader::parse(V1_TCPV4, Default::default()).unwrap();
        assert_eq!(consumed, V1_TCPV4.len());
        assert_eq!(
            res.0,
            Some(ProxiedAddress {
                protocol: Protocol::Stream,
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
                destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 443),
            })
        );
        assert_eq!(res.1, vec![0; 0]);

        let (res, consumed) = ProxyHeader::parse(V1_TCPV6, Default::default()).unwrap();

        assert_eq!(consumed, V1_TCPV6.len());
        assert_eq!(
            res.0,
            Some(ProxiedAddress {
                protocol: Protocol::Stream,
                source: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    12345
                ),
                destination: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    443
                ),
            })
        );
        assert_eq!(res.1, vec![0; 0]);
    }

    #[test]
    fn test_parse_proxy_header_v2() {
        let (res, consumed) = ProxyHeader::parse(V2_LOCAL, Default::default()).unwrap();
        assert_eq!(consumed, V2_LOCAL.len());
        assert_eq!(res.0, None);

        let (res, consumed) = ProxyHeader::parse(V2_TCPV4, Default::default()).unwrap();
        assert_eq!(consumed, V2_TCPV4.len());
        assert_eq!(
            res.0,
            Some(ProxiedAddress {
                protocol: Protocol::Stream,
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
                destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 443),
            })
        );

        let (res, consumed) = ProxyHeader::parse(V2_TCPV6, Default::default()).unwrap();
        assert_eq!(consumed, V2_TCPV6.len());
        assert_eq!(
            res.0,
            Some(ProxiedAddress {
                protocol: Protocol::Stream,
                source: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    12345
                ),
                destination: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    443
                ),
            })
        );
    }

    #[test]
    fn test_parse_proxy_header_with_tlvs() {
        let (res, _) = ProxyHeader::parse(
            V2_TCPV4_TLV,
            ParseConfig {
                include_tlvs: true,
                ..Default::default()
            },
        )
        .unwrap();

        use Tlv::*;

        let mut fields = res.tlvs();

        assert_eq!(fields.next(), Some(Ok(Crc32c(0xd399d8d8))));
        assert_eq!(fields.next(), Some(Ok(UniqueId(b"1234"[..].into()))));

        let ssl = fields.next().unwrap().unwrap();
        let ssl = match ssl {
            Tlv::Ssl(ssl) => ssl,
            _ => panic!("expected SSL TLV"),
        };

        assert!(ssl.verify() == 0);
        assert!(ssl.client_ssl());
        assert!(ssl.client_cert_conn());
        assert!(ssl.client_cert_sess());

        let mut f = ssl.tlvs();

        assert_eq!(f.next(), Some(Ok(SslVersion("TLSv1.3".into()))));
        assert_eq!(f.next(), Some(Ok(SslCn("localhost".into()))));
        assert_eq!(f.next(), Some(Ok(SslKeyAlg("RSA4096".into()))));
        assert_eq!(f.next(), Some(Ok(SslSigAlg("RSA-SHA256".into()))));
        assert_eq!(
            f.next(),
            Some(Ok(SslCipher("TLS_AES_256_GCM_SHA384".into())))
        );
        assert!(f.next().is_none());

        assert!(fields.next().is_none());
    }
}
