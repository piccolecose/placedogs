# CI

`.github/workflows/ci.yml` runs on every pull request and push to `main`. Both jobs must pass.

- `lint`: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`.
- `test`: `cargo cov` (alias in `.cargo/config.toml`), which runs the tests under `cargo-llvm-cov` and fails below 75% line coverage. The per-file summary goes to the job summary.

Run the same locally with `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo cov` (needs `cargo install cargo-llvm-cov`).

Raise the threshold in `.cargo/config.toml` when coverage goes up; never lower it to get a PR through.
