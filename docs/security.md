# Security notes

## Credentials and local files

`tshc` validates the selected credentials before starting `tsh`. Passwords must
not contain ASCII terminal control characters or DEL: the terminal would treat
them as editing, signal, or line-ending commands. Usernames and cluster labels
must not contain control characters either. Printable Unicode passwords work.

TOTP settings must contain a valid Base32 secret, a period from 1 to 300 seconds,
6 or 8 digits, and SHA1, SHA256, or SHA512. Omitted values default to 30 seconds,
6 digits, and SHA1. Duplicate parameters, malformed values, and nonnumeric
encoders are rejected without including the secret in the error.

Configuration and KeePass databases must be regular files. Configuration
symlinks are rejected; a KeePass database may be reached through a symlink.
Special files such as named pipes are rejected without waiting for input.

## Selector options

`fzf` keeps the user's appearance and key bindings. `tshc` overrides options
that change input/output framing or enable multiple selection, so the returned
cluster index remains unambiguous. After `fzf` exits or is canceled, waiting
for output pipes inherited by child processes is limited to one second.
User-defined hook processes may continue running independently.

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
