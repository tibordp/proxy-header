use criterion::{black_box, criterion_group, criterion_main, Criterion};
use proxy_header::ProxyHeader;

const V2_TCPV4_TLV: &[u8] = &[
    13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 104, 127, 0, 0, 1, 192, 168, 0, 1,
    48, 57, 1, 187, 3, 0, 4, 211, 153, 216, 216, 5, 0, 4, 49, 50, 51, 52, 32, 0, 75, 7, 0, 0, 0, 0,
    33, 0, 7, 84, 76, 83, 118, 49, 46, 51, 34, 0, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 37,
    0, 7, 82, 83, 65, 52, 48, 57, 54, 36, 0, 10, 82, 83, 65, 45, 83, 72, 65, 50, 53, 54, 35, 0, 22,
    84, 76, 83, 95, 65, 69, 83, 95, 50, 53, 54, 95, 71, 67, 77, 95, 83, 72, 65, 51, 56, 52,
];

const V1_TCPV4: &[u8] = b"PROXY TCP4 127.0.0.1 192.168.0.1 12345 443\r\n";

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("v2_tcpv4_tlv_full", |b| {
        b.iter(|| {
            let a = ProxyHeader::parse(
                black_box(V2_TCPV4_TLV),
                black_box(proxy_header::ParseConfig {
                    include_tlvs: true,
                    ..Default::default()
                }),
            )
            .unwrap();

            black_box(a.0.netns());
        })
    });

    c.bench_function("v2_tcpv4_tlv", |b| {
        b.iter(|| {
            ProxyHeader::parse(
                black_box(V2_TCPV4_TLV),
                black_box(proxy_header::ParseConfig {
                    include_tlvs: true,
                    ..Default::default()
                }),
            )
        })
    });

    c.bench_function("v2_tcpv4_tlv_no_tlv", |b| {
        b.iter(|| {
            ProxyHeader::parse(
                black_box(V2_TCPV4_TLV),
                black_box(proxy_header::ParseConfig {
                    include_tlvs: false,
                    ..Default::default()
                }),
            )
        })
    });

    c.bench_function("v1_tcpv4", |b| {
        b.iter(|| {
            ProxyHeader::parse(
                black_box(V1_TCPV4),
                black_box(proxy_header::ParseConfig {
                    include_tlvs: false,
                    ..Default::default()
                }),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
