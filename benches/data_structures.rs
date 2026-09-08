#![allow(missing_docs)]

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arcstr::ArcStr;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use smallvec::SmallVec;

use osdns::{DnsSuffix, ResourceId};

const IDS: [&str; 3] = [
    "linux:resolved:ifindex:7",
    "windows:interface:01234567-89ab-cdef-0123-456789abcdef",
    "macos:resolver:a-long-corporate-routing-domain.example.internal",
];

fn identifier_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("resource_id_clone");
    for input in IDS {
        group.throughput(Throughput::Elements(1));
        let string = input.to_owned();
        let arc: Arc<str> = Arc::from(input);
        let arcstr = ArcStr::from(input);
        group.bench_with_input(
            BenchmarkId::new("String", input.len()),
            &string,
            |b, value| {
                b.iter(|| black_box(value.clone()));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Arc_str", input.len()),
            &arc,
            |b, value| {
                b.iter(|| black_box(value.clone()));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("ArcStr", input.len()),
            &arcstr,
            |b, value| {
                b.iter(|| black_box(value.clone()));
            },
        );
    }
    group.finish();
}

fn production_identifier_clone(c: &mut Criterion) {
    let resource: ResourceId = IDS[1].parse().unwrap();
    let suffix = DnsSuffix::parse("a-long-corporate-routing-domain.example.internal").unwrap();
    let mut group = c.benchmark_group("production_identifier_clone");
    group.bench_function("ResourceId", |b| {
        b.iter(|| black_box(resource.clone()));
    });
    group.bench_function("DnsSuffix", |b| {
        b.iter(|| black_box(suffix.clone()));
    });
    group.finish();
}

fn identifier_map_lookup(c: &mut Criterion) {
    let strings: HashMap<String, usize> = IDS
        .iter()
        .enumerate()
        .map(|(index, value)| ((*value).to_owned(), index))
        .collect();
    let arcs: HashMap<Arc<str>, usize> = IDS
        .iter()
        .enumerate()
        .map(|(index, value)| (Arc::from(*value), index))
        .collect();
    let arcstrs: HashMap<ArcStr, usize> = IDS
        .iter()
        .enumerate()
        .map(|(index, value)| (ArcStr::from(*value), index))
        .collect();
    let mut group = c.benchmark_group("resource_id_map_lookup");
    group.bench_function("String", |b| {
        b.iter(|| black_box(strings.get(black_box(IDS[1]))));
    });
    group.bench_function("Arc_str", |b| {
        b.iter(|| black_box(arcs.get(black_box(IDS[1]))));
    });
    group.bench_function("ArcStr", |b| {
        b.iter(|| black_box(arcstrs.get(black_box(IDS[1]))));
    });
    group.finish();
}

fn dns_collection(c: &mut Criterion) {
    let values = [
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)),
    ];
    let mut group = c.benchmark_group("dns_collection_construct_clone");
    for len in 0..=4 {
        group.bench_with_input(BenchmarkId::new("Vec", len), &len, |b, &len| {
            b.iter(|| {
                let value = values[..len].to_vec();
                black_box(value.clone());
            });
        });
        group.bench_with_input(BenchmarkId::new("SmallVec_2", len), &len, |b, &len| {
            b.iter(|| {
                let value = SmallVec::<[IpAddr; 2]>::from_slice(&values[..len]);
                black_box(value.clone());
            });
        });
        group.bench_with_input(BenchmarkId::new("SmallVec_4", len), &len, |b, &len| {
            b.iter(|| {
                let value = SmallVec::<[IpAddr; 4]>::from_slice(&values[..len]);
                black_box(value.clone());
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    identifier_clone,
    production_identifier_clone,
    identifier_map_lookup,
    dns_collection
);
criterion_main!(benches);
