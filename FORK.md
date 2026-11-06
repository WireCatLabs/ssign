# WireCatLabs/ssign

A fork of [Le-Syl21/ssign](https://github.com/Le-Syl21/ssign), MIT like upstream. WireCat Desktop's release signs
the Windows installer with it, pinned to a full commit SHA of this repository.

Base: upstream `44335a75d23a0396c9f890e75fdfd60769cf377c` (`v0.1.10`).
The code is upstream's as is: our hardening patches were merged there in
[Le-Syl21/ssign#20](https://github.com/Le-Syl21/ssign/pull/20). `FORK.md` and `deny.toml` exist only here.

## Taking an upstream update

1. `git fetch https://github.com/Le-Syl21/ssign main` and read `git diff <base> FETCH_HEAD`. In `Cargo.lock`, only
   registry versions and checksums may move; a new crate needs a look at who publishes it.
2. Bring it in with a pull request. Actions are off here, so run the checks yourself:
   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   cargo test -p ssign-core --locked -- --ignored real_tsa
   cargo deny check
   ```
3. Squash-merge, update the base above, and pin the new `main` SHA in the release:
   `cargo install --locked --git https://github.com/WireCatLabs/ssign --rev <SHA> ssign`.
