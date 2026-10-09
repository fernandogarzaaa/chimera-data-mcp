# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added / Changed
- pytest smoke tests for the database, sandbox and server modules
- CI workflow (compile + pytest) on pushes to main and pull requests
- requirements.lock pinning transitive dependencies (uv pip compile, Python 3.12)
- Dependabot config for pip and GitHub Actions (weekly)
- SECURITY.md with private reporting contact
