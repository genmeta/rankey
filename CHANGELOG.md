# Changelog

## [0.3.0] - 2026-10-12

### Changed

- Migrate P-384, PKCS#8 and X.509 builders from release candidates to stable dependencies.
- Remove obsolete transitive release-candidate pins.
- Verify that generated CSRs preserve the P-384 key and reject modified signatures.

### Release versions

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `rankey` | 0.2.2 | 0.3.0 |
