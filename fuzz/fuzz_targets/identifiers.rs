#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    if let Ok(suffix) = input.parse::<osdns::DnsSuffix>() {
        let reparsed = suffix.to_string().parse::<osdns::DnsSuffix>().unwrap();
        assert_eq!(suffix, reparsed);
    }
    if let Ok(resource) = input.parse::<osdns::ResourceId>() {
        let reparsed = resource.to_string().parse::<osdns::ResourceId>().unwrap();
        assert_eq!(resource, reparsed);
    }
});
