use std::borrow::Cow;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::util::AddressFamily;
use crate::ParseConfig;
use crate::{
    Error::{self, *},
    Protocol, ProxiedAddress, ProxyHeader,
};

const GREETING: &[u8] = b"\r\n\r\n\x00\r\nQUIT\n";
const AF_UNIX_ADDRS_LEN: usize = 216;

fn parse_addrs<T: AddressFamily>(
    buf: &[u8],
    pos: &mut usize,
    rest: &mut usize,
    protocol: Protocol,
) -> Result<ProxiedAddress, Error> {
    if buf.len() < *pos + T::BYTES * 2 + 4 {
        return Err(BufferTooShort);
    }
    if *rest < T::BYTES * 2 + 4 {
        return Err(Invalid);
    }

    let ret = ProxiedAddress {
        protocol,
        source: SocketAddr::new(
            T::from_slice(&buf[*pos..*pos + T::BYTES]).to_ip_addr(),
            u16::from_be_bytes([buf[*pos + T::BYTES * 2], buf[*pos + T::BYTES * 2 + 1]]),
        ),
        destination: SocketAddr::new(
            T::from_slice(&buf[*pos + T::BYTES..*pos + T::BYTES * 2]).to_ip_addr(),
            u16::from_be_bytes([buf[*pos + T::BYTES * 2 + 2], buf[*pos + T::BYTES * 2 + 3]]),
        ),
    };

    *rest -= T::BYTES * 2 + 4;
    *pos += T::BYTES * 2 + 4;

    Ok(ret)
}

/// Decode a version 2 PROXY header from a buffer.
///
/// Returns the decoded header and the number of bytes consumed from the buffer.
pub fn decode(buf: &[u8], config: ParseConfig) -> Result<(ProxyHeader, usize), Error> {
    let mut pos = 0;

    if buf.len() < 4 + GREETING.len() {
        return Err(BufferTooShort);
    }
    if !buf.starts_with(GREETING) {
        return Err(Invalid);
    }
    pos += GREETING.len();

    let is_local = match buf[pos] {
        0x20 => true,
        0x21 => false,
        _ => return Err(Invalid),
    };
    let protocol = buf[pos + 1];
    let mut rest = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
    pos += 4;

    if buf.len() < pos + rest {
        return Err(BufferTooShort);
    }

    use Protocol::{Datagram, Stream};
    let addr_info = match protocol {
        0x00 => None,
        0x11 => Some(parse_addrs::<Ipv4Addr>(buf, &mut pos, &mut rest, Stream)?),
        0x12 => Some(parse_addrs::<Ipv4Addr>(buf, &mut pos, &mut rest, Datagram)?),
        0x21 => Some(parse_addrs::<Ipv6Addr>(buf, &mut pos, &mut rest, Stream)?),
        0x22 => Some(parse_addrs::<Ipv6Addr>(buf, &mut pos, &mut rest, Datagram)?),
        0x31 | 0x32 => {
            // AF_UNIX - we do not parse this, but don't reject it either in case
            // someone needs the TLVs

            if rest < AF_UNIX_ADDRS_LEN {
                return Err(Invalid);
            }
            rest -= AF_UNIX_ADDRS_LEN;
            pos += AF_UNIX_ADDRS_LEN;

            None
        }
        _ => return Err(Invalid),
    };

    let tlv_data = if config.include_tlvs {
        Cow::Borrowed(&buf[pos..pos + rest])
    } else {
        Default::default()
    };

    pos += rest;

    let header = if is_local {
        ProxyHeader(None, tlv_data)
    } else {
        ProxyHeader(addr_info, tlv_data)
    };

    Ok((header, pos))
}

pub fn encode<W: Write>(header: &ProxyHeader, buf: &mut W) -> Result<(), Error> {
    buf.write_all(GREETING).map_err(|_| BufferTooShort)?;

    match &header.0 {
        Some(ProxiedAddress {
            protocol,
            source: SocketAddr::V4(src),
            destination: SocketAddr::V4(dest),
        }) => {
            buf.write_all(b"\x21").map_err(|_| BufferTooShort)?;
            match protocol {
                Protocol::Stream => buf.write_all(b"\x11").map_err(|_| BufferTooShort)?,
                Protocol::Datagram => buf.write_all(b"\x12").map_err(|_| BufferTooShort)?,
            }

            let len: u16 = (4 + 4 + 2 + 2 + header.1.len())
                .try_into()
                .map_err(|_| HeaderTooBig)?;
            buf.write_all(&len.to_be_bytes())
                .map_err(|_| BufferTooShort)?;

            buf.write_all(&src.ip().octets())
                .map_err(|_| BufferTooShort)?;
            buf.write_all(&dest.ip().octets())
                .map_err(|_| BufferTooShort)?;
            buf.write_all(&src.port().to_be_bytes())
                .map_err(|_| BufferTooShort)?;
            buf.write_all(&dest.port().to_be_bytes())
                .map_err(|_| BufferTooShort)?;
        }
        Some(ProxiedAddress {
            protocol,
            source: SocketAddr::V6(src),
            destination: SocketAddr::V6(dest),
        }) => {
            buf.write_all(b"\x21").map_err(|_| BufferTooShort)?;
            match protocol {
                Protocol::Stream => buf.write_all(b"\x21").map_err(|_| BufferTooShort)?,
                Protocol::Datagram => buf.write_all(b"\x22").map_err(|_| BufferTooShort)?,
            }

            let len: u16 = (16 + 16 + 2 + 2 + header.1.len())
                .try_into()
                .map_err(|_| HeaderTooBig)?;
            buf.write_all(&len.to_be_bytes())
                .map_err(|_| BufferTooShort)?;

            buf.write_all(&src.ip().octets())
                .map_err(|_| BufferTooShort)?;
            buf.write_all(&dest.ip().octets())
                .map_err(|_| BufferTooShort)?;
            buf.write_all(&src.port().to_be_bytes())
                .map_err(|_| BufferTooShort)?;
            buf.write_all(&dest.port().to_be_bytes())
                .map_err(|_| BufferTooShort)?;
        }
        None => {
            buf.write_all(b"\x20\x00").map_err(|_| BufferTooShort)?;

            let len: u16 = header.1.len().try_into().map_err(|_| HeaderTooBig)?;
            buf.write_all(&len.to_be_bytes())
                .map_err(|_| BufferTooShort)?;
        }
        _ => return Err(AddressFamilyMismatch),
    }

    buf.write_all(&header.1).map_err(|_| BufferTooShort)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_encode_local() {
        let mut buf = [0u8; 1024];
        let header = ProxyHeader::with_local();

        let len = header.encode_to_slice_v2(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00");

        let decoded = decode(&buf, ParseConfig::default()).unwrap();
        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);
    }

    #[test]
    fn test_encode_ipv4() {
        let mut buf = [0u8; 102400];
        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Stream,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5678)),
        });

        let len = header.encode_to_slice_v2(&mut buf).unwrap();
        assert_eq!(
            &buf[..len],
            b"\r\n\r\n\x00\r\nQUIT\n!\x11\x00\x0c\x7f\x00\x00\x01\x7f\x00\x00\x01\x04\xd2\x16."
        );

        let decoded = decode(&buf, ParseConfig::default()).unwrap();
        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);
    }

    #[test]
    fn test_encode_ipv6() {
        let mut buf = [0u8; 102400];
        let header = ProxyHeader::with_address(ProxiedAddress {
            protocol: Protocol::Datagram,
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

        let len = header.encode_to_slice_v2(&mut buf).unwrap();
        assert_eq!(
            &buf[..len],
            &[
                13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 34, 0, 36, 32, 1, 13, 184, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4,
                210, 22, 46
            ]
        );

        let decoded = decode(&buf, ParseConfig::default()).unwrap();
        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);
    }

    #[test]
    fn test_tlvs() {
        let mut buf = [0u8; 102400];
        let mut header = ProxyHeader::with_local();
        header.append_tlv(crate::Tlv::UniqueId(b"unique"[..].into()));
        header.append_tlv(crate::Tlv::Crc32c(1234));

        let len = header.encode_to_slice_v2(&mut buf).unwrap();

        let decoded = decode(
            &buf,
            ParseConfig {
                include_tlvs: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(decoded.0, header);
        assert_eq!(decoded.1, len);

        assert_eq!(decoded.0.unique_id(), Some(&b"unique"[..]));
        assert_eq!(decoded.0.crc32c(), Some(1234));
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
            header.encode_to_slice_v2(&mut buf),
            Err(AddressFamilyMismatch)
        );
    }
}
