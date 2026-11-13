# Fuzz targets

Coverage-guided fuzzing (cargo-fuzz, libFuzzer) of the code that reads
untrusted input. Needs a nightly compiler and `cargo install cargo-fuzz`.

| Target | What it feeds |
| --- | --- |
| `vault_file` | `ParsedVault::parse`: a vault file from disk or a sync folder |
| `ipc_frame` | frames read by `vaultd` (requests) and by clients (replies) |
| `import_bitwarden` | a Bitwarden JSON export |
| `import_csv` | a browser password CSV |
| `qr_image` | a picture of a QR code ("Add Code" from an image) |

```sh
cd fuzz
cargo +nightly fuzz run vault_file -- -max_total_time=60
```

A crash is saved under `fuzz/artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> artifacts/<target>/<file>`. The GitHub
workflow `Fuzz` runs every target for a few minutes each week and on demand,
and uploads any crash as a build artifact.
