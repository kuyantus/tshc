# tshc

[![CI](https://github.com/kuyantus/tshc/actions/workflows/ci.yml/badge.svg)](https://github.com/kuyantus/tshc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

I built `tshc` because logging in to several Teleport clusters one by one got old. It reads local-login credentials from KeePass, runs `tsh login`, and lets you pick one cluster or sign in to all of them. TOTP can come from KeePass or from an authenticator on your phone.

![Cluster selector](tshc.png)

`tshc` is for Teleport's password-and-OTP login flow. It does not automate SSO or browser-based login.

## What you need

- `tsh` installed (in `PATH`, unless you set `tsh_path`)
- A KeePass `.kdbx` database with a `UserName` and `Password` in each Teleport entry
- Go 1.26 or newer if you install or build from source

[`fzf`](https://github.com/junegunn/fzf) is optional. With it, you get a searchable cluster list. Without it, `tshc` shows a numbered list in the terminal.

## Install

```bash
go install github.com/kuyantus/tshc@latest
```

Or, from a checkout of this repository:

```bash
go build -o tshc .
```

## First run

Run `tshc` once. It creates `~/.tshc/teleports.yaml` and stops so you can edit the file before any login is attempted. Your existing config is never replaced.

Here's a small example:

```yaml
keepass_db: /path/to/passwords.kdbx
keepass_password:
  source: keychain

teleports:
  - name: work
    proxy: teleport.example.com
    keepass_entry: Teleport/work
    totp_source: prompt
    tsh_args:
      - --ttl=480
```

Replace the database path, proxy address, and KeePass entry path with your own. `keepass_entry` is relative to the database's root group: use `group/entry`, or just `entry` if it is in the root group. The optional `tsh_args` list is passed to `tsh login`; `--ttl=480` requests 480 minutes (eight hours), subject to your Teleport cluster's limits.

On macOS, run `tshc keychain set` to save the KeePass master password in your default Keychain. The system asks for the password in the terminal; `tshc` does not put it in the config or a command-line argument. If you prefer to enter it every time, set `keepass_password.source: prompt`. On Linux, and when Keychain is unavailable, `tshc` asks for it in the terminal.

Now run `tshc` again and choose a cluster. Select `[ALL]` to log in to each configured cluster in turn.

## TOTP and other options

Set `totp_source` on each cluster:

- `prompt` asks for a code when `tsh` requests one. Use this for an authenticator on another device.
- `keepass` generates a code from the KeePass entry's `otp` field. That field must contain an `otpauth://totp/...` URI. This is the default if `totp_source` is omitted.

You can also set `login_timeout` (default `5m`), or provide absolute `tsh_path` and `fzf_path` values if the executables are not in `PATH`. The generated [configuration template](teleports.yaml) shows the layout.

For command help and the installed version:

```bash
tshc --help
tshc --version
```

## A note about Keychain

Keychain avoids typing the KeePass master password on every run, but this is not Touch ID protection. Depending on the item's access settings, macOS may allow it to be read while your account is unlocked without another confirmation. Use `source: prompt` if you want to enter the password each time. `tshc keychain delete` removes the saved item.

If you previously created this item with `security add-generic-password -A`, remove it and create it again with `tshc keychain set`: `-A` allows any application to access it without warning. Updating its password is not a substitute for reviewing its access settings.

## License

[MIT](LICENSE)
