# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-14

The first version of the core under its own numbering; the engine and its command api share one version.

### Added

- Read and write KeePass KDBX 4 databases: a password, a key file, or both; AES-256 and ChaCha20, Argon2d / Argon2id
  and AES-KDF.
- Entries and groups: custom fields, attachments, history, recycle bin, search, TOTP.
- Merge of two copies of one database and import of another database.
- A password generator.
- `pass-api`: the command api the apps call - json in, json out - and `CORE_VERSION`.

[Unreleased]: https://github.com/BigToEstDev/kdbx-rust-core/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/BigToEstDev/kdbx-rust-core/releases/tag/v1.0.0
