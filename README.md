# tshc

[![CI](https://github.com/kuyantus/tshc/actions/workflows/ci.yml/badge.svg)](https://github.com/kuyantus/tshc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`tshc` is an interactive CLI for signing in to one or more Teleport clusters with credentials stored in a KeePass database. It can generate TOTP codes from KeePass or wait for a code entered from another device.

![tshc interface](tshc.png)

## Features

- Reads usernames, passwords, and TOTP settings from a KeePass (`.kdbx`) database
- Supports TOTP codes generated from KeePass or entered manually, for example from a phone
- Stores the KeePass master password in the macOS Login Keychain for unattended startup
- Falls back to secure terminal input when Keychain is unavailable
- Uses `fzf` for interactive cluster selection
- Passes configured arguments to `tsh login`
- Signs in to all selected clusters sequentially to avoid races over the shared `tsh` profile

## Requirements

- Go 1.26 or later when installing or building from source
- [Teleport CLI](https://goteleport.com/docs/connect-your-client/tsh/)
- A KeePass database containing the Teleport credentials
- `fzf` for interactive selection

Install `fzf` on macOS:

```bash
brew install fzf
```

Install `fzf` on Ubuntu or Debian:

```bash
sudo apt install fzf
```

## Installation

Install the latest version with Go:

```bash
go install github.com/kuyantus/tshc@latest
```

Or build a cloned repository:

```bash
go build -o tshc
```

The project does not use CGO, so macOS and Linux binaries can be cross-compiled with `CGO_ENABLED=0`.

## Quick start

Run `tshc` once:

```bash
tshc
```

On first run, `tshc` creates the private directory `~/.tshc` and writes an embedded configuration template to `~/.tshc/teleports.yaml`. Edit that file with the path to your KeePass database and your Teleport clusters, then run `tshc` again. The existing configuration is never overwritten, and no template file is required next to the binary.

On macOS, store the KeePass master password in Login Keychain to start `tshc` without entering it each time:

```bash
tshc keychain set
```

On Linux, or when `keepass_password.source` is set to `prompt`, `tshc` securely asks for the master password in the terminal without echoing it.

## Configuration

Example `~/.tshc/teleports.yaml`:

```yaml
keepass_db: /Users/you/passwords.kdbx
keepass_password:
  source: keychain
login_timeout: 5m

# Optional absolute paths protect against PATH-based executable substitution.
# tsh_path: /opt/homebrew/bin/tsh
# fzf_path: /opt/homebrew/bin/fzf

teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: teleport/production
    totp_source: keepass
    tsh_args:
      - --ttl=480

  - name: staging
    proxy: staging.teleport.example.com
    keepass_entry: teleport/staging
    totp_source: prompt
```

### KeePass settings

- `keepass_db` is the path to the KeePass database.
- `keepass_entry` is the path to an entry in the form `group/entry`. Use only the entry name when it is stored in the root group.
- `keepass_password.source` controls how the database master password is obtained. `keychain` is the default: on macOS it reads a regular item from Login Keychain, and on other systems or when Keychain is unavailable it falls back to terminal input. `prompt` always asks in the terminal without echoing the password.

### TOTP settings

- `totp_source: keepass` generates a code from the KeePass entry's `otp` field and is the default.
- `totp_source: prompt` waits for the MFA request from `tsh` and asks for a code in the terminal. Use it when the authenticator is on another device.

When manual TOTP is enabled, `tshc` shows the current cluster name and address before asking for the code. It hides the low-level password and TOTP prompts from `tsh`, while preserving warnings, errors, and the final login result.

### Teleport settings

- `name` is the local display name of the cluster.
- `proxy` is the Teleport proxy address.
- `tsh_args` contains optional extra arguments for `tsh login`. In the example, `--ttl=480` requests an eight-hour session.
- `login_timeout` is the maximum duration of a single login and defaults to `5m`. It must be greater than zero. When `[ALL]` is selected, a timeout for one cluster does not prevent attempts to sign in to the remaining clusters.
- `tsh_path` and `fzf_path` are optional absolute executable paths. Absolute paths are preferable for a credential-forwarding tool because they avoid substitution through `PATH`.

When an executable is resolved, it must belong to root or the current user and must not be writable by the group or everyone. Each parent directory must also belong to root or the current user and must not be world-writable. Group-writable directories owned by the current user are allowed to support standard Homebrew layouts.

Selecting `[ALL]` signs in to the configured clusters sequentially.

## macOS Keychain

Store or update the KeePass master password:

```bash
tshc keychain set
```

Delete it:

```bash
tshc keychain delete
```

`tshc` invokes `/usr/bin/security add-generic-password` directly without a shell. The system utility asks for the password in the terminal, so the secret is not passed through process arguments, environment variables, or a shell command line. The stored item uses the service `teleport-login` and account `keepass`.

After reading the password, `tshc` keeps it in memory only until the KeePass database is opened and then clears its buffer. The absolute `/usr/bin/security` path prevents command substitution through `PATH`, and the amount of secret data read from the command is limited.

Using Login Keychain is a deliberate convenience and security tradeoff: the password is encrypted at rest, but after the user signs in to macOS the item can be read without a separate Touch ID confirmation. Do not create the item with `security add-generic-password -A`, because that permits access by any application. Enable FileVault, protect the macOS account with a strong password, and lock the screen when leaving the computer.

## Usage

Start the interactive cluster selector:

```bash
tshc
```

Show help or the version:

```bash
tshc --help
tshc --version
```

Embed a version in a release binary:

```bash
go build -trimpath -ldflags "-s -w -X main.version=v1.0.0" -o tshc
```

The configuration directory is created with mode `0700` and the configuration file with mode `0600`. `tshc` refuses to use symbolic links in their place. Manual KeePass passwords and TOTP codes are read without echo and respond to Ctrl-C. On SIGINT the process exits with status 130; on SIGTERM it exits with status 143.

## License

[MIT](LICENSE) permits use, modification, and redistribution while retaining the license text and copyright notice.
