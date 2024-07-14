use std::io::Write;
use std::net::SocketAddr;
use std::str::from_utf8;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::util::{read_until, AddressFamily};
use crate::{
    Error::{self, *},
    Protocol, ProxiedAddress, ProxyHeader,
};

const MAX_LENGTH: usize = 107;
const GREETING: &[u8] = b"PROXY";

fn parse_addr<T: AddressFamily>(buf: &[u8], pos: &mut usize) -> Result<T, Error> {
    let Some(address) = read_until(&buf[*pos..], b' ') else {
        return Err(BufferTooShort);
    };

    let addr = from_utf8(address)
        .map_err(|_| Invalid)
        .and_then(|s| T::from_str(s).map_err(|_| Invalid))?;
    *pos += address.len() + 1;

    Ok(addr)
}

fn parse_port(buf: &[u8], pos: &mut usize, terminator: u8) -> Result<u16, Error> {
    let Some(port) = read_until(&buf[*pos..], terminator) else {
        return Err(BufferTooShort);
    };

    let p = from_utf8(port)
        .map_err(|_| Invalid)
        .and_then(|s| u16::from_str(s).map_err(|_| Invalid))?;
    *pos += port.len() + 1;

    Ok(p)
}

fn parse_addrs<T: AddressFamily>(buf: &[u8], pos: &mut usize) -> Result<ProxiedAddress, Error> {
    let src_addr: T = parse_addr(buf, pos)?;
    let dst_addr: T = parse_addr(buf, pos)?;
    let src_port = parse_port(buf, pos, b' ')?;
    let dst_port = parse_port(buf, pos, b'\r')?;

    Ok(ProxiedAddress {
        protocol: Protocol::Stream, // v1 header only supports TCP
        source: SocketAddr::new(src_addr.to_ip_addr(), src_port),
        destination: SocketAddr::new(dst_addr.to_ip_addr(), dst_port),
    })
}

fn decode_inner(buf: &[u8]) -> Result<(ProxyHeader, usize), Error> {
    let mut pos = 0;

    if buf.len() < b"PROXY UNKNOWN\r\n".len() {
        // All other valid PROXY headers are longer than this.
        return Err(BufferTooShort);
    }
    if !buf.starts_with(GREETING) {
        return Err(Invalid);
    }
    pos += GREETING.len() + 1;

    let addrs = if buf[pos..].starts_with(b"UNKNOWN") {
        let Some(rest) = read_until(&buf[pos..], b'\r') else {
            return Err(BufferTooShort);
        };
        pos += rest.len() + 1;

        None
    } else {
        let proto = &buf[pos..pos + 5];
        pos += 5;

        match proto {
            b"TCP4 " => Some(parse_addrs::<Ipv4Addr>(buf, &mut pos)?),
            b"TCP6 " => Some(parse_addrs::<Ipv6Addr>(buf, &mut pos)?),
            _ => return Err(Invalid),
        }
    };

    match buf.get(pos) {
        Some(b'\n') => pos += 1,
        None => return Err(BufferTooShort),
        _ => return Err(Invalid),
    }

    Ok((ProxyHeader(addrs, Default::default()), pos))
}

/// Decode a version 1 PROXY header from a buffer.
///
/// Returns the decoded header and the number of bytes consumed from the buffer.
pub fn decode(buf: &[u8]) -> Result<(ProxyHeader, usize), Error> {
    // Guard against a malicious client sending a very long header, since it is a
    // delimited protocol.

    match decode_inner(buf) {
        Err(Error::BufferTooShort) if buf.len() >= MAX_LENGTH => Err(Error::Invalid),
        other => other,
    }
}

pub fn encode<W: Write>(header: &ProxyHeader, writer: &mut W) -> Result<(), Error> {
    if !header.1.is_empty() {
        return Err(V1UnsupportedTlv);
    }
    writer.write_all(GREETING).map_err(|_| BufferTooShort)?;
    writer.write_all(b" ").map_err(|_| BufferTooShort)?;

    match header.0 {
        Some(ProxiedAddress {
            protocol: Protocol::Stream,
            source,
            destination,
        }) => match (source, destination) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                write!(
                    writer,
                    "TCP4 {} {} {} {}\r\n",
                    src.ip(),
                    dst.ip(),
                    src.port(),
                    dst.port()
                )
                .map_err(|_| BufferTooShort)?;
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                write!(
                    writer,
                    "TCP6 {} {} {} {}\r\n",
                    src.ip(),
                    dst.ip(),
                    src.port(),
                    dst.port()
                )
                .map_err(|_| BufferTooShort)?;
            }
            _ => return Err(AddressFamilyMismatch),
        },
        None => {
            writer
                .write_all(b"UNKNOWN\r\n")
                .map_err(|_| BufferTooShort)?;
        }
        _ => return Err(V1UnsupportedProtocol),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn test_encode_local() {
        let mut buf = [0u8; 1024];
        let header = ProxyHeader::with_local();

        let len = header.encode_to_slice_v1(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"PROXY UNKNOWN\r\n");

        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);
    }

    #[test]
    fn test_encode_ipv4() {
        let mut buf = [0u8; 1024];
        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5678)),
        });

        let len = header.encode_to_slice_v1(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"PROXY TCP4 127.0.0.1 8.8.4.4 1234 5678\r\n");

        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);
    }

    #[test]
    fn test_encode_ipv6() {
        let mut buf = [0u8; 1024];
        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                1234,
                0,
                0,
            )),
            destination: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                5678,
                0,
                0,
            )),
        });

        let len = header.encode_to_slice_v1(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"PROXY TCP6 2001:db8::1 ::1 1234 5678\r\n");

        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);
    }

    #[test]
    fn test_tlvs() {
        let mut buf = [0u8; 1024];
        let mut header = ProxyHeader::with_local();
        header.append_tlv(crate::Tlv::Noop(10));

        assert_eq!(header.encode_to_slice_v1(&mut buf), Err(V1UnsupportedTlv));
    }

    #[test]
    fn test_family_mismatch() {
        let mut buf = [0u8; 1024];
        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            destination: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                5678,
                0,
                0,
            )),
        });

        assert_eq!(
            header.encode_to_slice_v1(&mut buf),
            Err(AddressFamilyMismatch)
        );
    }

    #[test]
    fn test_buffer_too_short() {
        let mut buf = [0u8; 1024];
        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5678)),
        });

        assert_eq!(
            header.encode_to_slice_v1(&mut buf[0..10]),
            Err(BufferTooShort)
        );
    }
}
