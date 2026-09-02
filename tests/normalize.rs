//! Normalization and `DnsSuffix` behavior.
use osdns::DnsSuffix;
use rstest::rstest;

fn canonical(input: &str) -> String {
    DnsSuffix::parse(input).unwrap().to_string()
}

#[test]
fn normalizes_case_and_trailing_dot() {
    assert_eq!(canonical("Example.COM"), "example.com");
    assert_eq!(canonical("example.com."), "example.com");
    assert_eq!(canonical("  example.com  "), "example.com");
    assert_eq!(canonical("EXAMPLE.com."), "example.com");
}

#[rstest]
#[case("MÜNCHEN.example", "xn--mnchen-3ya.example")]
#[case("münchen.example", "xn--mnchen-3ya.example")]
#[case("bücher.example", "xn--bcher-kva.example")]
#[case("例え.テスト", "xn--r8jz45g.xn--zckzah")]
fn applies_idna_uts46(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(canonical(input), expected);
}

#[test]
fn root_domain_representation() {
    let root = DnsSuffix::parse(".").unwrap();
    assert!(root.is_root());
    assert_eq!(root, DnsSuffix::root());
    assert_eq!(root.as_str(), "");
    assert_eq!(root.to_string(), ".");
    assert_eq!(DnsSuffix::parse("").unwrap(), root);
    assert_eq!(canonical(" . "), ".");
}

#[test]
fn rejects_invalid_domains() {
    let bad = [
        "a..b",
        ".abc.com",
        "abc..com",
        "-abc.com",
        "abc-.com",
        "a_b.example",
        "a b.com",
        "*.example.com",
        "ex!ample.com",
        "ab--cd.example",
    ];
    for input in bad {
        assert!(
            DnsSuffix::parse(input).is_err(),
            "expected {input:?} to be rejected"
        );
    }
}

#[test]
fn rejects_overlong_labels_and_domains() {
    let long_label = format!("{}.example", "a".repeat(64));
    assert!(DnsSuffix::parse(&long_label).is_err());

    let long_domain = ["a".repeat(60).as_str(); 5].join(".");
    assert!(DnsSuffix::parse(&long_domain).is_err());
}

#[test]
fn accepts_boundary_lengths() {
    let label = "a".repeat(63);
    assert!(DnsSuffix::parse(&label).is_ok());
    let domain = ["a".repeat(49).as_str(); 5].join(".");
    assert!(DnsSuffix::parse(&domain).is_ok());
}

#[test]
fn display_roundtrip() {
    for input in ["example.com", "xn--mnchen-3ya.example", "."] {
        let parsed = DnsSuffix::parse(input).unwrap();
        let reparsed = DnsSuffix::parse(&parsed.to_string()).unwrap();
        assert_eq!(parsed, reparsed);
    }
}

#[test]
fn serde_roundtrip() {
    let domain = DnsSuffix::parse("Example.COM.").unwrap();
    let json = serde_json::to_string(&domain).unwrap();
    assert_eq!(json, "\"example.com\"");
    let back: DnsSuffix = serde_json::from_str(&json).unwrap();
    assert_eq!(domain, back);

    let root = DnsSuffix::root();
    let json = serde_json::to_string(&root).unwrap();
    assert_eq!(json, "\".\"");
    let back: DnsSuffix = serde_json::from_str(&json).unwrap();
    assert_eq!(root, back);
}

#[test]
fn serde_rejects_invalid() {
    let result: Result<DnsSuffix, _> = serde_json::from_str("\"a..b\"");
    assert!(result.is_err());
}
