# WireCatLabs/ssign

A fork of [Le-Syl21/ssign](https://github.com/Le-Syl21/ssign), MIT like upstream. WireCat Desktop's release signs
the Windows installer with it, pinned to a full commit SHA of this repository.

Base: upstream `222cb903731d385ab75e37e88564bcf4cb100458` (`v0.1.9`).

## Patches

Each is also a branch cut from upstream `main`, ready to offer upstream:

| Branch | Change |
| --- | --- |
| `upstream/certum-origin` | The bearer token and the login form go only to `https://cloudsign.webnotarius.pl` |
| `upstream/hide-env-values` | `--help` names `CERTUM_*` but never prints their values |
| `upstream/zeroize-otp` | The TOTP seed and the token are wiped after use; bad otpauth `digits`/`period` are refused |
| `upstream/timestamp-nonce` | The timestamp reply must echo the request's nonce and imprint |
| `upstream/verify-signature` | Certum's signature is checked against the certificate before it is embedded |

`FORK.md` and `deny.toml` exist only here.

## Taking an upstream update

1. `git fetch https://github.com/Le-Syl21/ssign main` and read `git diff <base> FETCH_HEAD`. In `Cargo.lock`, only
   registry versions and checksums may move.
2. Rebase the patches onto it in a pull request. Actions are off here, so run the checks yourself:
   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   cargo test -p ssign-core --locked -- --ignored real_tsa
   cargo deny check
   ```
3. Squash-merge, update the base above, and pin the new `main` SHA in the release:
   `cargo install --locked --git https://github.com/WireCatLabs/ssign --rev <SHA> ssign`.
