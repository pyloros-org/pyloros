# cargo-fuzz crate needs its own `[workspace]` table

The `fuzz/` crate is intentionally **not** a member of the root workspace, but
cargo walks up the directory tree from `fuzz/Cargo.toml`, finds the root
`Cargo.toml`'s `[workspace]`, and errors with:

```
error: current package believes it's in a workspace when it's not
```

Adding `fuzz` to the root `exclude` list does **not** fix this. The canonical
cargo-fuzz fix is an empty `[workspace]` table at the top of `fuzz/Cargo.toml`,
which makes the fuzz crate its own workspace root:

```toml
[workspace]

[package]
name = "pyloros-fuzz"
...
```

Without it, `cargo +nightly fuzz run/check` fails before compiling anything.
