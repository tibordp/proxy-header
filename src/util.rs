use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

pub fn read_until(buf: &[u8], delim: u8) -> Option<&[u8]> {
    for i in 0..buf.len() {
        if buf[i] == delim {
            return Some(&buf[..i]);
        }
    }
    None
}

pub trait AddressFamily: FromStr {
    const BYTES: usize;

    fn to_ip_addr(self) -> IpAddr;
    fn from_slice(slice: &[u8]) -> Self;
}

impl AddressFamily for Ipv4Addr {
    const BYTES: usize = 4;

    fn to_ip_addr(self) -> IpAddr {
        IpAddr::V4(self)
    }

    fn from_slice(slice: &[u8]) -> Self {
        let arr: [u8; 4] = slice.try_into().expect("slice must be 4 bytes");
        arr.into()
    }
}

impl AddressFamily for Ipv6Addr {
    const BYTES: usize = 16;

    fn to_ip_addr(self) -> IpAddr {
        IpAddr::V6(self)
    }

    fn from_slice(slice: &[u8]) -> Self {
        let arr: [u8; 16] = slice.try_into().expect("slice must be 16 bytes");
        arr.into()
    }
}

macro_rules! tlv {
    ($self:expr, $kind:ident) => {{
        $self.tlvs().find_map(|f| match f {
            Ok(crate::Tlv::$kind(v)) => Some(v),
            _ => None,
        })
    }};
}

macro_rules! tlv_borrowed {
    ($self:expr, $kind:ident) => {{
        $self.tlvs().find_map(|f| match f {
            Ok(crate::Tlv::$kind(v)) => match v {
                // It is more ergonomic to return the borrowed value directly rather
                // than it wrapped in a `Cow::Borrowed`. We know that tlvs always borrows
                // so we can safely unwrap the `Cow::Borrowed` and return the borrowed value.
                Cow::Owned(_) => unreachable!(),
                Cow::Borrowed(v) => Some(v),
            },
            _ => None,
        })
    }};
}

pub(crate) use {tlv, tlv_borrowed};
