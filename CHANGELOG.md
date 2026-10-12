# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `run_python_analytics` now runs analyst code in a resource-limited child
  process with no file descriptors, an audit hook and allow-listed pandas/numpy
  facades. Previously `pd.read_csv`, `df.to_csv` and `pd.read_pickle` could
  read/write server files (Oct 2026 audit).
- `execute_readonly_query` uses a read-only connection (SQLite `mode=ro` +
  authorizer; PostgreSQL/MySQL read-only sessions) and caps results at
  `MAX_QUERY_ROWS` (default 1000).
- Adversarial tests for both.
- Added MIT LICENSE.

### Added / Changed
- pytest smoke tests for the database, sandbox and server modules
- CI workflow (compile + pytest) on pushes to main and pull requests
- requirements.lock pinning transitive dependencies (uv pip compile, Python 3.12)
- Dependabot config for pip and GitHub Actions (weekly)
- SECURITY.md with private reporting contact
