#![no_main]
//! Fuzz the git packfile parser used for force-push ancestry checks.
//!
//! Goal: `pack_contains_ancestry` must never panic, hang, or consume
//! unbounded memory on arbitrary input. Returns are limited to one of three
//! enum variants — even malformed packs should funnel into `Indeterminate`.
//!
//! Input layout: first 40 bytes (if present) provide the `old` and `new`
//! SHAs to walk between; remaining bytes are treated as the pack body.

use libfuzzer_sys::fuzz_target;
use pyloros::filter::pack::pack_contains_ancestry;

fuzz_target!(|data: &[u8]| {
    let (old, new, pack) = if data.len() >= 40 {
        let mut o = [0u8; 20];
        let mut n = [0u8; 20];
        o.copy_from_slice(&data[..20]);
        n.copy_from_slice(&data[20..40]);
        (o, n, &data[40..])
    } else {
        ([0u8; 20], [0xffu8; 20], data)
    };
    let _ = pack_contains_ancestry(pack, &old, &new);
});
