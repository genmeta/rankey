# Release preparation for v0.3.0

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `rankey` | 0.2.2 | 0.3.0 |

## Dependency order

No unpublished Genmeta upstream dependencies.

Manifest versions use Cargo's compatible-version requirements, without `=`.
They allow patch updates within the selected 0.x series. External Genmeta
dependencies come from crates.io; no sibling checkout or Git patch is required.
The dquic TLS backend is the published qrustls 0.23.45 package, used as `rustls`
where the application exchanges TLS types with qtls.

## Validation and lockfiles

This PR is release preparation. Unpublished upstream versions can make CI fail;
such failures do not confirm compilation, tests or package verification.
Cargo.lock is not tracked for this library. CI resolves and checks the release graph.
Run Cargo from a checkout outside directories containing ancestor path patches.
Never commit a lockfile generated with local transport path overrides as the
registry release lockfile. Re-run the normal CI checks and publish dry run after
upstream publication and lockfile refresh; merge and tag only that checked commit.

## Publication

Planned tag: `v0.3.0`. Release through the repository's GitHub Actions workflow.
Use an annotated tag with the changelog entry as its release notes. Actual
publication and production deployment remain separate from this preparation PR.

The v0.3.0 tag publishes the rankey crate and creates its GitHub Release
after the publication step succeeds. The tag must match Cargo.toml.
