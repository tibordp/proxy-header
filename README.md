# proxy-header

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/proxy-header.svg
[crates-url]: https://crates.io/crates/proxy-header
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/tibordp/proxy-header/blob/main/LICENSE
[actions-badge]: https://github.com/tibordp/proxy-header/workflows/Rust/badge.svg
[actions-url]: https://github.com/tibordp/proxy-header/actions?query=workflow%3ARust+branch%3Amain

This crate provides a decoder and encoder for the
[HAProxy PROXY protocol](https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt),
which is used to preserve original client connection information when proxying TCP
connections for protocols that do not support this higher up in the stack.

The PROXY protocol is supported by many load balancers and proxies, including HAProxy,
Amazon ELB, Amazon ALB, and others.

This crate implements the entire specification, except parsing the `AF_UNIX` address
type (the header is validated / parsed, but the address is not decoded or exposed in
the API).

## Acknowledgements

This crate started as a fork of the [`proxy-protocol`](https://crates.io/crates/proxy-protocol)
crate, but has since been rewritten from scratch.

## License

This crate is licensed under the MIT license. See the `LICENSE` file for details.
