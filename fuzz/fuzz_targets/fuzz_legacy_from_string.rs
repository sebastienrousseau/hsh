#![no_main]
//! Legacy `Hash::from_string` parser must never panic on arbitrary input.
//! This is the pre-PHC 6-part dollar-delimited format that we retain
//! for backwards compatibility.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = hsh::models::hash::Hash::from_string(s);
    let _ = hsh::models::hash::Hash::parse_algorithm(s);
});
