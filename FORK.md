# WireCatLabs/ssign

This is WireCat's fork of [Le-Syl21/ssign](https://github.com/Le-Syl21/ssign). WireCat Desktop's release workflow uses
it to sign the Windows installer with Certum SimplySign. The code is upstream's, under upstream's MIT licence
([LICENSE](LICENSE)).

## Why the fork exists

- **Availability.** The release pins a full commit SHA here. A deleted upstream repository or a taken-over upstream
  account cannot change what we build.
- **Hardening.** Six small patches close the paths where the Certum session token or a one-time code could leave
  Certum's origin, and add checks before a signature is embedded. They came out of a security review of upstream.

## Base

Upstream `222cb903731d385ab75e37e88564bcf4cb100458` (tag `v0.1.9`).

## Our patches

| Patch | Pull request | What it changes |
| --- | --- | --- |
| P1 | [#1](https://github.com/WireCatLabs/ssign/pull/1) | `client.rs`: an `atom:link` poll URL must be https on `cloudsign.webnotarius.pl`, default port, no userinfo, or the bearer token is not sent. The API client is `https_only` |
| P2 | [#1](https://github.com/WireCatLabs/ssign/pull/1) | `auth.rs`: the login follows redirects only within that origin and fails on any other hop, so a 307/308 cannot re-send the login form elsewhere. Login and final URLs are checked. `https_only` |
| P3 | [#2](https://github.com/WireCatLabs/ssign/pull/2) | `main.rs`: `--help` names `CERTUM_EMAIL`, `CERTUM_OTP` and `CERTUM_TOKEN` but never prints their values |
| P6 | [#2](https://github.com/WireCatLabs/ssign/pull/2) | `otp.rs`, `auth.rs`, `session.rs`: the decoded seed and the session token are `Zeroizing`. `otpauth://` with `digits` outside 6..=8 or `period=0` is rejected |
| P4 | [#3](https://github.com/WireCatLabs/ssign/pull/3) | `timestamp.rs`: the RFC 3161 request carries a random nonce. The reply must echo it and the SHA-256 imprint of our signature. The TSA's CMS signature is left to Windows |
| P5 | [#3](https://github.com/WireCatLabs/ssign/pull/3) | `authenticode.rs`: Certum's signature is verified with the certificate's public key (aws-lc-rs) before it is embedded |

Not changed on purpose: `ssign-pkcs11`, `msi.rs`, the docs and upstream's `.github/`. GitHub Actions are disabled on
this fork, so upstream's release jobs never run here.

## Reviewing an upstream update

1. Fetch upstream and read every change since the base:
   `git fetch https://github.com/Le-Syl21/ssign main` then `git diff 222cb90 FETCH_HEAD`. Read all source changes.
   For `Cargo.lock`, check that only registry versions and checksums move: no git sources, no new registries.
2. Rebase our patches onto the new upstream commit on a branch, and resolve conflicts.
3. Run the checks below. Actions are disabled, so these are the CI:
   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   cargo test -p ssign-core --locked -- --ignored real_tsa   # Certum's public TSA, no account
   cargo audit
   cargo deny check                                           # uses deny.toml here
   cargo tree --locked -p ssign --target x86_64-pc-windows-msvc -e normal,build
   ```
   `cargo audit` reports advisories for crates that are never built (quinn-proto, as optional reqwest features) or
   are dev-only (rsa). Compare its output with the previous review, and look only for new entries.
4. Merge by pull request with a squash, update the base commit and the table above, then pin the new `main` SHA in
   the release workflow:
   `cargo install --locked --git https://github.com/WireCatLabs/ssign --rev <full SHA>`.
