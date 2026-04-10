# Changelog

All notable changes to ShrouDB Stash are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [v0.1.10] - 2026-04-09

### Added

- validate client-encrypted blob integrity on STORE

## [v0.1.9] - 2026-04-09

- Version bump release

## [v0.1.8] - 2026-04-09

### Added

- streaming encryption, blob-ID AAD, event model adaptation, rewrap
- adapt to chronicle-core 1.3.0 event model

## [v0.1.6] - 2026-04-04

### Changed

- use shared ServerAuthConfig from shroudb-acl

## [v0.1.5] - 2026-04-02

### Fixed

- use entrypoint script to fix volume mount permissions

### Other

- Use check_dispatch_acl for consistent ACL error formatting

## [v0.1.4] - 2026-04-01

### Other

- Replace bare unwrap on RNG fill with descriptive expect in test helpers

## [v0.1.3] - 2026-04-01

### Other

- Add concurrent/failure/expansion tests from ENGINE_REVIEW_v6

## [v0.1.2] - 2026-04-01

### Other

- Clarify forensic fingerprinting is for leak tracing, not deduplication

## [v0.1.0] - 2026-04-01

### Other

- Cipher-less raw passthrough, comprehensive tests, AGENTS.md
- Comprehensive integration tests with MinIO S3 backend
- Add 13 integration tests for Stash engine
- Add CI and release workflows
- Add server, client, CLI crates and infrastructure
- Apply rustfmt formatting
- Add documentation and protocol spec
- Add version specifiers for workspace deps (required for publishing)
- Add .gitignore, remove target from tracking
- Initial Stash engine implementation (v0.1)

