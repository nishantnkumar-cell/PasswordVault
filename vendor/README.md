# Patched third-party crates

Each folder here is an unchanged copy of a crates.io release plus one
upstream fix, used through `[patch.crates-io]` in the top-level `Cargo.toml`.
They are not workspace members (`exclude = ["vendor"]`), so `cargo fmt` and
`clippy` leave them as upstream wrote them.

Delete a folder, and its `[patch]` line, as soon as everything that uses it
has moved to a fixed release.

## ml-dsa (0.0.4 + RustCrypto/signatures#1144)

- **Why:** RUSTSEC-2025-0144 (CVE-2026-22705). `Decompose` divided a value
  derived from the secret key with a hardware division instruction, whose
  timing depends on its input, during every ML-DSA signature. The vault signs
  with ML-DSA-65 through `pgp` 0.21 (post-quantum OpenPGP keys, `vault pgp
  new --pq`). `pgp` 0.21, its newest release, requires `ml-dsa` 0.0.4; the
  fix shipped in `ml-dsa` 0.1.0-rc.3, whose API is different.
- **Change:** commit `035d9ee` from
  [RustCrypto/signatures](https://github.com/RustCrypto/signatures/commit/035d9eef98486ecd00a8bf418c7817eb14dd6558)
  applied to `src/algebra.rs` and `src/ntt.rs` without changes (Barrett
  reduction in place of the division; fixed loop bounds in the NTT). The
  rest of the folder is the crates.io 0.0.4 release byte for byte.
- **Checked:** the crate's own tests pass (`cargo test --all-features`; the
  `pkcs8` test needs `RUST_MIN_STACK=67108864` in debug builds, as it does
  without the patch). The new division gives the same result as `/` for
  every field element (0 to q-1) and both ML-DSA divisors (190464 and
  523776). The vault's post-quantum OpenPGP round-trip tests pass.
- **Remove when:** `pgp` moves to `ml-dsa` 0.1 (rpgp/rpgp#573).
- **Licence:** Apache-2.0 OR MIT (`LICENSE-APACHE`, `LICENSE-MIT`).
