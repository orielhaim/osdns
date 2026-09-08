#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = osdns::testing::parse_resolv_conf_for_fuzzing(bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        let entries: Vec<String> = text.split('\0').map(str::to_owned).collect();
        osdns::testing::parse_linux_domains_for_fuzzing(&entries);
        #[cfg(target_os = "windows")]
        osdns::testing::parse_windows_strings_for_fuzzing(text);
    }
});
