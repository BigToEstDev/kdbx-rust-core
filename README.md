# kdbx-rust-core

A Rust library for reading, writing and merging KeePass KDBX 4 password databases.

**Status:** the engine of the KDBX Vault apps (Android and desktop). Not published on crates.io; the API is
pre-1.0 and changes together with the apps.

## Features

- Open and save KDBX 4 databases with a password, a key file, or both.
- Create new databases and key files.
- Entries and groups: custom fields, tags, history, recycle bin, attachments, custom icons.
- Search across entries.
- TOTP codes for entries.
- Merge a copy of the same database, in either direction, and import entries from another database.
- Password generator and password strength analysis.
- Pure Rust: no C dependencies and no `unsafe` code (`#![forbid(unsafe_code)]`).

## Compatibility

| | Supported | Not supported |
|---|---|---|
| File format | KDBX 4.0 and 4.1 (read); saves as 4.1 | KDBX 2.x / 3.x, KeePass 1.x (`.kdb`) — rejected with an error |
| Outer cipher | AES-256, ChaCha20 | Twofish |
| Key derivation | Argon2id (default for new databases), Argon2d | AES-KDF |
| Inner stream | ChaCha20 | Salsa20 |
| Compression | GZip or none | — |
| Key files | XML 1.0 and 2.0, 32-byte binary, 64-character hex, any other file (hashed) — as KeePass and KeePassXC read them; new key files are written as XML 2.0 | — |
| TOTP | `otpauth://totp/` URIs and the KeePass `TimeOtp-*` fields | HOTP, Steam Guard |

The files are meant to be shared with KeePassXC, KeePass and KeePassDX. Test fixtures are generated, and
saved databases are checked, with an independent implementation of the format (pykeepass), so a mistake made
the same way in our reader and writer cannot pass unnoticed.

## Repository layout

| Path | Contents |
|---|---|
| `crates/kdbx-rust-core` | The engine: the KDBX format, cryptography, database content, merge |
| `crates/pass-api` | The command API the apps call: a command name and JSON arguments in, a JSON result out. Shared by the Android and desktop apps, with its contract files in `contract/` |
| `tools/kdbx-oracle` | Python scripts on pykeepass: fixture generation and save round-trip checks |

## Usage

The crates are not published. They are used by [kdbx-vault-android](https://github.com/BigToEstDev/kdbx-vault-android)
through a native bridge (JNI on Android, a shared library on desktop). To depend on them from another
project, use a git dependency:

```toml
[dependencies]
kdbx-rust-core = { git = "https://github.com/BigToEstDev/kdbx-rust-core" }
```

## Building and testing

Built and tested with Rust 1.98 (stable) on Windows x86_64 (MSVC); the exact toolchain is pinned in
`rust-toolchain.toml` — install it with `rustup toolchain install`. Android builds go through the bridge in
kdbx-vault-android, with `cargo-ndk`.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The test fixtures are committed; Python is not needed to run the tests. `tools/kdbx-oracle` (Python 3,
pykeepass — see its README) regenerates the fixtures and checks a database saved by this library.

The `xml-dump` feature is for development only: it writes the whole decrypted database, passwords included,
to a file. It is off by default, not part of the API, and enabled for the test build only.

## Security

- Secrets held in memory are wiped with `zeroize`; the `Debug` output of types that hold secrets is redacted.
- No network access: the library works with the bytes of a database and its key file only.

**Reporting a vulnerability:** please use
[private vulnerability reporting](https://github.com/BigToEstDev/kdbx-rust-core/security/advisories/new) on
GitHub, not a public issue. Other bugs and questions go to
[issues](https://github.com/BigToEstDev/kdbx-rust-core/issues).

## Contributing

Pull requests are not accepted. Bug reports and questions are welcome in issues.

## Licence and origin

GPL-3.0-only — see `LICENSE`.

This project descends from [onekeepass-core](https://github.com/OneKeePass/onekeepass-core) by jeyasankar,
licensed under the GPLv3. It has since been developed independently: the API, the cryptography layer, the XML
handling and the tests have diverged, and upstream changes are not merged.

The licence covers the code, not the name: "KDBX Vault" and its logo are not licensed under the GPLv3. Forks
are welcome under their own name.

## Acknowledgements

- jeyasankar, the author of onekeepass-core, the original implementation this library grew from.
- [pykeepass](https://github.com/libkeepass/pykeepass), the independent implementation the tests are checked
  against.
