#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = osdns::testing::decode_journal_for_fuzzing(bytes);
});
