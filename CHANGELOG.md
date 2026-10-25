# Changelog

## [0.1.5] — 2026-10-25

- Reject malformed or repeated TOTP parameters and invalid Base32 secrets before starting a login. Explicit invalid periods no longer silently become 30 seconds; Steam codes are rejected.
- Parse TOTP settings once. On an Apple M2 Max with Go 1.27.3, ten benchmark runs showed 83–85% less parsing time and 95–96% fewer allocated bytes. These figures measure settings parsing, not the complete login.
- Preserve the original login error when cleaning up `tsh`, including invalid OTP input and repeated password prompts.
- Reject terminal control characters in KeePass credentials and cluster labels before they can alter terminal input or display.
- Reject FIFO and other special files immediately when opening configuration or KeePass databases. KeePass database symlinks remain supported.
- Bound waiting for inherited `fzf` output pipes after cancellation or exit. Enforce single-selection output despite conflicting `FZF_DEFAULT_OPTS`; reject ambiguous responses.
- Update `gokeepasslib` to 3.7.1, including fixes for panics on truncated databases, `x/crypto` to 0.58.0, and `x/sys` to 0.49.0.
- Require Go 1.27.3 or newer for source builds. Refresh gosec, govulncheck, and golangci-lint versions in CI.

Earlier release notes are available in [GitHub Releases].

[0.1.5]: https://github.com/kuyantus/tshc/compare/v0.1.4...v0.1.5
[GitHub Releases]: https://github.com/kuyantus/tshc/releases
