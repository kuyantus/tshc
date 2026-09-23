# Contributing

Use Go 1.26.8 or newer, with the latest security fixes for your Go release.
From a checkout, run:

```bash
go test -race -shuffle=on ./...
go vet ./...
golangci-lint run ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -exclude-dir=.agents ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.4.0 ./...
go mod tidy -diff
```

Tests use synthetic credentials and local executable fixtures. They do not
need a Teleport server or access to your saved Keychain passwords. The macOS
permission dialog needs a separate manual check
with a disposable Keychain item; the unit tests check the command arguments.

Keep changes focused and use Conventional Commits, for example
`fix(keychain): require confirmation for new items`. CI runs on macOS and
Linux, tests the minimum Go version and the current stable version, and pins
third-party actions to commit SHAs. Keep the adjacent version comments when
updating those pins; Dependabot is configured to propose updates.

## Release procedure

1. Run the checks above on the release commit. Review the CI results for both
   supported operating systems and Go versions.
2. Build release binaries with a supported, patched Go toolchain. Check each
   binary's toolchain with `go version -m /path/to/binary`; changing `go.mod`
   or updating your local compiler does not repair existing binaries.
3. Configure your maintainer signing key in Git. Create an annotated, signed
   tag for the new version and verify its signature before publishing:

   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z"
   git verify-tag vX.Y.Z
   ```

   Replace `vX.Y.Z` with the actual version. A signed commit does not sign the
   tag pointing to it. Verification also requires trusting the maintainer's
   signing key through the configured Git signing backend.
4. Publish the verified tag and any rebuilt artifacts through the normal
   release process. Record the toolchain version used for binary builds.

Do not replace published tags to add signatures retroactively. Existing
unsigned releases remain unsigned; use a new signed tag for the next release.
