# Security notes

## Executable validation

On macOS, `tshc` accepts parent directories writable by the `admin` group,
including Homebrew's `Cellar` and `/Applications`. This trusts the Mac's
administrators to manage installed software. Files and directories must
still be owned by you or root, executable files must not be group- or
world-writable, and world-writable directories are rejected.

If an automatically discovered `fzf` fails validation, `tshc` explains why and
uses the numbered selector. An invalid explicit `fzf_path` still produces an error.

For a custom shared installation, the optional `trusted_executable_groups`
list can name groups allowed to write executable parent directories. Enable
it only for groups whose members you trust to replace those executables.
Standard macOS Homebrew does not need this setting.
