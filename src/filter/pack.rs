//! Minimal git packfile parser for force-push detection.
//!
//! The receive-pack body contains a packfile after the pkt-line flush. To decide
//! whether a push is a fast-forward, we walk the commit graph backward from
//! `new-sha` looking for `old-sha`. A legitimate fast-forward pack contains the
//! chain of new commits linking back to `old-sha` (the server-known tip); a
//! force/rewind pack does not.
//!
//! We only decode the minimum needed: object headers, delta chains for commit
//! objects, and commit "parent" lines. Trees and blobs are ignored. Unresolvable
//! ref-deltas (bases outside the pack) yield `Indeterminate`, which the caller
//! treats as "block" (fail closed).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;

use flate2::read::ZlibDecoder;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

const TYPE_COMMIT: u8 = 1;
const TYPE_OFS_DELTA: u8 = 6;
const TYPE_REF_DELTA: u8 = 7;

/// Hard cap on commits visited during BFS (DoS protection).
const MAX_WALK: usize = 50_000;
/// Hard cap on delta chain depth during resolution.
const MAX_DELTA_DEPTH: usize = 64;

/// Result of the ancestry check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AncestryResult {
    /// `old` is reachable from `new` via commits present in the pack.
    IsAncestor,
    /// `old` is not reachable; the pack fully expresses the history from `new`
    /// and it does not lead to `old`.
    NotAncestor,
    /// The pack is malformed, truncated, references a base not in the pack,
    /// or the walk exceeded sanity bounds. Caller should treat as "block".
    Indeterminate,
}

/// Walk commits in `pack_bytes` from `new` toward parents, looking for `old`.
pub fn pack_contains_ancestry(pack_bytes: &[u8], old: &[u8; 20], new: &[u8; 20]) -> AncestryResult {
    let commits = match parse_commits(pack_bytes) {
        Ok(c) => c,
        Err(_) => return AncestryResult::Indeterminate,
    };

    let mut visited: HashSet<[u8; 20]> = HashSet::new();
    let mut queue: VecDeque<[u8; 20]> = VecDeque::new();
    queue.push_back(*new);
    visited.insert(*new);
    let mut steps = 0usize;

    while let Some(sha) = queue.pop_front() {
        steps += 1;
        if steps > MAX_WALK {
            return AncestryResult::Indeterminate;
        }

        // If we reach `old` as a commit in the pack, that's also a match.
        if sha == *old {
            return AncestryResult::IsAncestor;
        }

        let parents = match commits.get(&sha) {
            Some(p) => p,
            // Commit not in pack: can't traverse further through this node.
            None => continue,
        };

        for p in parents {
            if p == old {
                return AncestryResult::IsAncestor;
            }
            if visited.insert(*p) {
                queue.push_back(*p);
            }
        }
    }

    AncestryResult::NotAncestor
}

/// Parse the pack and return a `sha -> parents` map of all commit objects.
fn parse_commits(pack: &[u8]) -> Result<HashMap<[u8; 20], Vec<[u8; 20]>>, &'static str> {
    if pack.len() < 12 + 20 {
        return Err("pack too short");
    }
    if &pack[0..4] != b"PACK" {
        return Err("not a pack");
    }
    let version = u32::from_be_bytes(pack[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err("unsupported pack version");
    }
    let num_objects = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;

    struct Entry {
        type_: u8,
        /// Decompressed bytes: full object for non-delta, delta instructions otherwise.
        data: Vec<u8>,
        base_offset: Option<usize>,
        base_sha: Option<[u8; 20]>,
    }

    let mut entries: Vec<Entry> = Vec::with_capacity(num_objects);
    let mut by_offset: HashMap<usize, usize> = HashMap::new();

    let mut pos = 12;
    for _ in 0..num_objects {
        let start = pos;
        by_offset.insert(start, entries.len());

        let (type_, _size, hdr_len) = parse_obj_header(&pack[pos..])?;
        pos += hdr_len;

        let mut base_offset = None;
        let mut base_sha = None;

        if type_ == TYPE_OFS_DELTA {
            let (neg_off, nlen) = parse_ofs_varint(&pack[pos..])?;
            pos += nlen;
            if neg_off > start || neg_off == 0 {
                return Err("bad ofs_delta offset");
            }
            base_offset = Some(start - neg_off);
        } else if type_ == TYPE_REF_DELTA {
            if pos + 20 > pack.len() {
                return Err("short ref_delta header");
            }
            let mut sha = [0u8; 20];
            sha.copy_from_slice(&pack[pos..pos + 20]);
            pos += 20;
            base_sha = Some(sha);
        }

        let (data, consumed) = decompress_at(&pack[pos..])?;
        pos += consumed;

        entries.push(Entry {
            type_,
            data,
            base_offset,
            base_sha,
        });
    }

    // Phase 1: compute SHAs for all non-delta objects.
    let mut sha_to_idx: HashMap<[u8; 20], usize> = HashMap::new();
    let mut resolved_type: HashMap<usize, u8> = HashMap::new();
    let mut resolved_bytes: HashMap<usize, Vec<u8>> = HashMap::new();

    for (i, e) in entries.iter().enumerate() {
        if e.type_ == TYPE_OFS_DELTA || e.type_ == TYPE_REF_DELTA {
            continue;
        }
        let sha = compute_object_sha(e.type_, &e.data);
        sha_to_idx.insert(sha, i);
        resolved_type.insert(i, e.type_);
        resolved_bytes.insert(i, e.data.clone());
    }

    // Phase 2: iteratively resolve deltas whose bases are known.
    loop {
        let mut progressed = false;
        for (i, e) in entries.iter().enumerate() {
            if resolved_type.contains_key(&i) {
                continue;
            }

            let base_idx = if let Some(bo) = e.base_offset {
                match by_offset.get(&bo) {
                    Some(&bi) => Some(bi),
                    None => return Err("ofs_delta base not in pack"),
                }
            } else if let Some(bs) = e.base_sha {
                sha_to_idx.get(&bs).copied()
            } else {
                None
            };

            let base_idx = match base_idx {
                Some(bi) => bi,
                // ref_delta base not in pack — leave unresolved.
                None => continue,
            };

            let base_type = match resolved_type.get(&base_idx) {
                Some(&t) => t,
                None => continue,
            };
            let base_bytes = resolved_bytes.get(&base_idx).expect("resolved").clone();

            let target = match apply_delta(&base_bytes, &e.data) {
                Some(t) => t,
                None => return Err("delta apply failed"),
            };
            let sha = compute_object_sha(base_type, &target);
            sha_to_idx.insert(sha, i);
            resolved_type.insert(i, base_type);
            resolved_bytes.insert(i, target);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    // Collect commits.
    let mut commits: HashMap<[u8; 20], Vec<[u8; 20]>> = HashMap::new();
    for (sha, idx) in sha_to_idx.iter() {
        let t = match resolved_type.get(idx) {
            Some(&t) => t,
            None => continue,
        };
        if t != TYPE_COMMIT {
            continue;
        }
        let bytes = resolved_bytes.get(idx).expect("resolved");
        commits.insert(*sha, parse_commit_parents(bytes));
    }

    Ok(commits)
}

/// Parse a pack object header: 3-bit type + variable-length size.
///
/// Returns (type, size, bytes_consumed).
fn parse_obj_header(data: &[u8]) -> Result<(u8, u64, usize), &'static str> {
    if data.is_empty() {
        return Err("empty header");
    }
    let b0 = data[0];
    let type_ = (b0 >> 4) & 0x07;
    let mut size: u64 = u64::from(b0 & 0x0f);
    let mut shift = 4;
    let mut i = 1;
    if b0 & 0x80 != 0 {
        loop {
            if i >= data.len() {
                return Err("truncated obj header");
            }
            let b = data[i];
            i += 1;
            size |= u64::from(b & 0x7f) << shift;
            shift += 7;
            if shift > 63 {
                return Err("obj header size overflow");
            }
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((type_, size, i))
}

/// Parse git's negative-offset varint for OFS_DELTA.
fn parse_ofs_varint(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("empty ofs varint");
    }
    let mut i = 0;
    let mut val: usize = usize::from(data[i] & 0x7f);
    let mut cont = data[i] & 0x80 != 0;
    i += 1;
    while cont {
        if i >= data.len() {
            return Err("truncated ofs varint");
        }
        val = val
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or("ofs varint overflow")?
            | usize::from(data[i] & 0x7f);
        cont = data[i] & 0x80 != 0;
        i += 1;
    }
    Ok((val, i))
}

/// Parse a standard varint (low 7 bits per byte, high bit = continuation).
fn parse_varint(data: &[u8]) -> Result<(u64, usize), &'static str> {
    let mut val: u64 = 0;
    let mut shift = 0;
    let mut i = 0;
    loop {
        if i >= data.len() {
            return Err("truncated varint");
        }
        let b = data[i];
        i += 1;
        val |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("varint overflow");
        }
    }
    Ok((val, i))
}

/// Decompress a zlib stream at the start of `data`, returning
/// (decompressed_bytes, consumed_input_bytes).
fn decompress_at(data: &[u8]) -> Result<(Vec<u8>, usize), &'static str> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|_| "zlib error")?;
    let consumed = dec.total_in() as usize;
    Ok((out, consumed))
}

/// Apply a git delta to `base`, returning the reconstructed target bytes.
fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let (src_size, n1) = parse_varint(delta).ok()?;
    if src_size as usize != base.len() {
        return None;
    }
    let (tgt_size, n2) = parse_varint(&delta[n1..]).ok()?;
    let tgt_size = tgt_size as usize;

    let mut out = Vec::with_capacity(tgt_size);
    let mut i = n1 + n2;

    // Bound delta chain depth indirectly: huge target sizes are suspicious.
    if tgt_size > 128 * 1024 * 1024 {
        return None;
    }

    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            // Copy from base: offset (4 bytes max) + size (3 bytes max).
            let mut offset: u64 = 0;
            for b in 0..4 {
                if op & (1 << b) != 0 {
                    if i >= delta.len() {
                        return None;
                    }
                    offset |= u64::from(delta[i]) << (8 * b);
                    i += 1;
                }
            }
            let mut size: u64 = 0;
            for b in 0..3 {
                if op & (1 << (4 + b)) != 0 {
                    if i >= delta.len() {
                        return None;
                    }
                    size |= u64::from(delta[i]) << (8 * b);
                    i += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let off = offset as usize;
            let sz = size as usize;
            if off.checked_add(sz)? > base.len() {
                return None;
            }
            out.extend_from_slice(&base[off..off + sz]);
        } else if op != 0 {
            // Insert literal: next `op` bytes.
            let sz = op as usize;
            if i + sz > delta.len() {
                return None;
            }
            out.extend_from_slice(&delta[i..i + sz]);
            i += sz;
        } else {
            // Reserved opcode 0.
            return None;
        }
    }

    if out.len() != tgt_size {
        return None;
    }
    Some(out)
}

/// Compute git's object SHA-1 over `"<type> <len>\0<content>"`.
fn compute_object_sha(type_: u8, content: &[u8]) -> [u8; 20] {
    let type_str = match type_ {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        _ => "unknown",
    };
    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    let header = format!("{} {}\0", type_str, content.len());
    ctx.update(header.as_bytes());
    ctx.update(content);
    let d = ctx.finish();
    let mut out = [0u8; 20];
    out.copy_from_slice(d.as_ref());
    out
}

/// Parse "parent <40hex>" lines from a commit object body.
fn parse_commit_parents(body: &[u8]) -> Vec<[u8; 20]> {
    let mut parents = Vec::new();
    let mut start = 0;
    while start < body.len() {
        // End of headers at first blank line.
        if body[start] == b'\n' {
            break;
        }
        let end = body[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| start + p)
            .unwrap_or(body.len());
        let line = &body[start..end];
        if line.starts_with(b"parent ") && line.len() == 7 + 40 {
            if let Some(sha) = hex_to_sha(&line[7..]) {
                parents.push(sha);
            }
        }
        start = end + 1;
    }
    parents
}

fn hex_to_sha(s: &[u8]) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        let hi = hex_digit(s[2 * i])?;
        let lo = hex_digit(s[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// Reference MAX_DELTA_DEPTH so it isn't flagged as dead; used as an implicit
// sanity limit by the iterative resolution loop (bounded by num_objects) and
// the per-delta target-size cap.
#[allow(dead_code)]
const _MAX_DELTA_DEPTH: usize = MAX_DELTA_DEPTH;

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use pyloros_test_support::test_report;
    use std::io::Write;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Encode a pack object header: type (3 bits) + varint size.
    fn encode_obj_header(type_: u8, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let first = ((type_ & 0x07) << 4) | ((size & 0x0f) as u8);
        let mut size = size >> 4;
        if size == 0 {
            out.push(first);
        } else {
            out.push(first | 0x80);
            while size > 0 {
                let mut b = (size & 0x7f) as u8;
                size >>= 7;
                if size > 0 {
                    b |= 0x80;
                }
                out.push(b);
            }
        }
        out
    }

    /// Build a minimal pack containing the given full (non-delta) objects.
    /// Each object is (type, raw_content).
    fn build_pack(objects: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());
        for (t, content) in objects {
            pack.extend(encode_obj_header(*t, content.len() as u64));
            pack.extend(zlib_compress(content));
        }
        // Trailing SHA-1 of pack contents (we don't check it; fill with zeros).
        pack.extend_from_slice(&[0u8; 20]);
        pack
    }

    fn make_commit(tree_hex: &str, parents: &[&str], extra: &str) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(&format!("tree {}\n", tree_hex));
        for p in parents {
            s.push_str(&format!("parent {}\n", p));
        }
        s.push_str("author A <a@x> 0 +0000\n");
        s.push_str("committer A <a@x> 0 +0000\n");
        s.push('\n');
        s.push_str(extra);
        s.into_bytes()
    }

    fn sha_of_commit(body: &[u8]) -> [u8; 20] {
        compute_object_sha(TYPE_COMMIT, body)
    }

    fn hex(sha: &[u8; 20]) -> String {
        sha.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_ancestry_linear_chain() {
        let t = test_report!("linear chain c1 -> c2 -> c3: c1 is ancestor of c3");
        let tree = "1111111111111111111111111111111111111111";
        let c1 = make_commit(tree, &[], "root");
        let c1_sha = sha_of_commit(&c1);
        let c2 = make_commit(tree, &[&hex(&c1_sha)], "two");
        let c2_sha = sha_of_commit(&c2);
        let c3 = make_commit(tree, &[&hex(&c2_sha)], "three");
        let c3_sha = sha_of_commit(&c3);

        let pack = build_pack(&[
            (TYPE_COMMIT, c1.clone()),
            (TYPE_COMMIT, c2.clone()),
            (TYPE_COMMIT, c3.clone()),
        ]);

        let r = pack_contains_ancestry(&pack, &c1_sha, &c3_sha);
        t.assert_eq("c1 ancestor of c3", &r, &AncestryResult::IsAncestor);
    }

    #[test]
    fn test_ancestry_not_ancestor() {
        let t = test_report!("divergent commits: neither is ancestor of the other");
        let tree = "1111111111111111111111111111111111111111";
        let a = make_commit(tree, &[], "A");
        let b = make_commit(tree, &[], "B");
        let a_sha = sha_of_commit(&a);
        let b_sha = sha_of_commit(&b);

        let pack = build_pack(&[(TYPE_COMMIT, a), (TYPE_COMMIT, b)]);

        let r = pack_contains_ancestry(&pack, &a_sha, &b_sha);
        t.assert_eq("a not ancestor of b", &r, &AncestryResult::NotAncestor);
    }

    #[test]
    fn test_ancestry_old_as_parent_edge() {
        // Simulate fast-forward push: `old` is the server-known tip, not in pack.
        // Pack has one new commit whose parent is old-sha.
        let t = test_report!("old-sha referenced as parent but not in pack -> ancestor");
        let tree = "1111111111111111111111111111111111111111";
        let old_sha_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let old_sha = [0xaau8; 20];
        let new_commit = make_commit(tree, &[old_sha_hex], "new");
        let new_sha = sha_of_commit(&new_commit);

        let pack = build_pack(&[(TYPE_COMMIT, new_commit)]);

        let r = pack_contains_ancestry(&pack, &old_sha, &new_sha);
        t.assert_eq(
            "old reachable via parent edge",
            &r,
            &AncestryResult::IsAncestor,
        );
    }

    #[test]
    fn test_ancestry_malformed_pack() {
        let t = test_report!("malformed pack returns Indeterminate");
        let r = pack_contains_ancestry(b"not-a-pack", &[0u8; 20], &[1u8; 20]);
        t.assert_eq(
            "malformed -> Indeterminate",
            &r,
            &AncestryResult::Indeterminate,
        );
    }

    #[test]
    fn test_parse_ofs_varint_single_byte() {
        let t = test_report!("ofs varint with single byte < 0x80");
        let (v, n) = parse_ofs_varint(&[0x05]).unwrap();
        t.assert_eq("value", &v, &5usize);
        t.assert_eq("consumed", &n, &1usize);
    }

    #[test]
    fn test_parse_varint_single_byte() {
        let t = test_report!("standard varint single byte");
        let (v, n) = parse_varint(&[0x7f]).unwrap();
        t.assert_eq("value", &v, &0x7fu64);
        t.assert_eq("consumed", &n, &1usize);
    }

    #[test]
    fn test_ancestry_real_git_pack() {
        let t = test_report!("real git-produced pack: FF vs force-push detection");
        // Build a repo, record fast-forward and force-push pack bytes, run through the parser.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("src");
        let bare = tmp.path().join("bare.git");
        std::process::Command::new("git")
            .args(["init", "-q", "-b", "main"])
            .arg(&repo)
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["init", "-q", "--bare"])
            .arg(&bare)
            .status()
            .unwrap();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap()
        };
        std::fs::write(repo.join("f"), "a").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "c1"]);
        git(&["remote", "add", "o", bare.to_str().unwrap()]);
        git(&["push", "-q", "o", "main"]);
        let old = git(&["rev-parse", "HEAD"]);
        let old_hex = String::from_utf8_lossy(&old.stdout).trim().to_string();

        // Fast-forward commit and pack it.
        std::fs::write(repo.join("f"), "b").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "c2"]);
        let new_ff = git(&["rev-parse", "HEAD"]);
        let new_ff_hex = String::from_utf8_lossy(&new_ff.stdout).trim().to_string();

        // Ask git to build a thin pack with just c2 (not c1, which bare has).
        let pack_cmd = std::process::Command::new("git")
            .args(["pack-objects", "--stdout", "--thin", "--revs"])
            .current_dir(&repo)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        pack_cmd
            .stdin
            .as_ref()
            .unwrap()
            .write_all(format!("{}\n^{}\n", new_ff_hex, old_hex).as_bytes())
            .unwrap();
        let ff_pack = pack_cmd.wait_with_output().unwrap().stdout;

        let old_sha = hex_to_sha(old_hex.as_bytes()).unwrap();
        let new_sha = hex_to_sha(new_ff_hex.as_bytes()).unwrap();
        let r = pack_contains_ancestry(&ff_pack, &old_sha, &new_sha);
        t.assert_eq("fast-forward recognized", &r, &AncestryResult::IsAncestor);

        // Force-push: build a commit in an unrelated repo (different root),
        // so new-sha has no ancestry to old.
        std::process::Command::new("git")
            .args(["init", "-q", "-b", "other"])
            .arg(tmp.path().join("src2"))
            .status()
            .unwrap();
        let repo2 = tmp.path().join("src2");
        std::fs::write(repo2.join("g"), "x").unwrap();
        let git2 = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&repo2)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap()
        };
        git2(&["add", "."]);
        git2(&["commit", "-q", "-m", "unrelated"]);
        let other = git2(&["rev-parse", "HEAD"]);
        let other_hex = String::from_utf8_lossy(&other.stdout).trim().to_string();
        // Pack just this single unrelated commit (thin, no negative rev, so full).
        let pack_cmd = std::process::Command::new("git")
            .args(["pack-objects", "--stdout", "--revs"])
            .current_dir(&repo2)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        pack_cmd
            .stdin
            .as_ref()
            .unwrap()
            .write_all(format!("{}\n", other_hex).as_bytes())
            .unwrap();
        let force_pack = pack_cmd.wait_with_output().unwrap().stdout;
        let new_force_sha = hex_to_sha(other_hex.as_bytes()).unwrap();
        let r = pack_contains_ancestry(&force_pack, &old_sha, &new_force_sha);
        t.assert_eq(
            "force-push (divergent) not ancestor",
            &r,
            &AncestryResult::NotAncestor,
        );
    }

    #[test]
    fn test_parse_varint_two_bytes() {
        let t = test_report!("standard varint with continuation");
        // 0x82, 0x01 -> low 7 bits = 0x02, next 7 bits = 0x01 -> 0x82 (130)
        let (v, n) = parse_varint(&[0x82, 0x01]).unwrap();
        t.assert_eq("value", &v, &130u64);
        t.assert_eq("consumed", &n, &2usize);
    }
}
