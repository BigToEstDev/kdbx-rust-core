# kdbx-rust-core

A pure Rust library for KeePass KDBX 4 databases: read, write, merge, search, entry types, password
generation and TOTP. Platform independent, with no C dependencies and no `unsafe`
(`#![forbid(unsafe_code)]`). It is the core of the KDBX Vault apps; the Android bridge lives in a separate
crate, because JNI cannot be written here.

Supported: KDBX 4.0 / 4.1, AES-256 and ChaCha20, Argon2d / Argon2id, ChaCha20 inner stream. KDBX 3.x and
KeePass 1 files are rejected rather than half read.

## Origin and licence

This project descends from [onekeepass-core](https://github.com/OneKeePass/onekeepass-core) by jeyasankar,
licensed under the GPLv3. It is **no longer a fork in practice**: the public api, the crypto layer, the xml
handling and the test suite have diverged far enough that upstream changes are not merged any more, and the
project is developed independently under its own name.

Because the code descends from GPLv3 code, **this library and anything linking it stay under the GPLv3** —
see `LICENSE` for the full text. Credit for the original implementation belongs to its author; every change
since the split is recorded in this repository's commit history.

## Building and testing

```bash
cargo test                                  # unit + integration tests, fixtures are committed
cargo clippy --all-targets -- -D warnings   # required before every commit
cargo fmt --check
```

Optional features, both off by default and not part of the public api: `xml-dump` (a development-only dump
of the decrypted xml) and `csv-import` (the parked csv import). They are enabled for the test build through
a cyclic dev-dependency on this crate, so `cargo test` covers them without extra flags.

The `tools/kdbx-oracle/` scripts use pykeepass as an independent implementation of the format: they
generate the test fixtures and compare a database before and after our own save, so a symmetric mistake in
our reader and writer cannot pass unnoticed. Python is not needed for `cargo test`.
