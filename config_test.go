package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureConfigInstallsBundledConfig(t *testing.T) {
	t.Parallel()

	home := t.TempDir()

	var output bytes.Buffer
	configPath, created, err := ensureConfig(home, &output)
	if err != nil {
		t.Fatalf("ensureConfig() error = %v", err)
	}
	if !created {
		t.Fatal("ensureConfig() did not report a new configuration")
	}
	wantPath := filepath.Join(home, configDirName, configFileName)
	if configPath != wantPath {
		t.Errorf("config path = %q, want %q", configPath, wantPath)
	}
	installed, err := os.ReadFile(configPath) // #nosec G304 -- configPath is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, defaultConfig) {
		t.Errorf("installed config does not match embedded default")
	}
	if !strings.Contains(output.String(), configPath) {
		t.Errorf("output = %q, want copied config path", output.String())
	}

	directoryInfo, err := os.Stat(filepath.Dir(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("config directory permissions = %o, want 700", got)
	}
	fileInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("config permissions = %o, want 600", got)
	}
	installedConfig, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("load embedded config: %v", err)
	}
	if len(installedConfig.Teleports) == 0 {
		t.Fatal("embedded config has no Teleport entries")
	}

	output.Reset()
	secondPath, created, err := ensureConfig(home, &output)
	if err != nil {
		t.Fatalf("second ensureConfig() error = %v", err)
	}
	if created {
		t.Fatal("second ensureConfig() reported an existing configuration as new")
	}
	if secondPath != configPath {
		t.Errorf("second config path = %q, want %q", secondPath, configPath)
	}
	if output.Len() != 0 {
		t.Errorf("second ensureConfig() output = %q, want none", output.String())
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		yaml               string
		wantSource         totpSource
		wantPasswordSource keepassPasswordSource
		wantTimeout        time.Duration
		wantError          string
	}{
		{
			name: "defaults to keepass TOTP",
			yaml: `keepass_db: /tmp/passwords.kdbx
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
`,
			wantSource:         totpSourceKeePass,
			wantPasswordSource: keepassPasswordSourceKeychain,
			wantTimeout:        defaultLoginTimeout,
		},
		{
			name: "manual TOTP and custom timeout",
			yaml: `keepass_db: /tmp/passwords.kdbx
keepass_password:
  source: prompt
login_timeout: 90s
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
    totp_source: prompt
`,
			wantSource:         totpSourcePrompt,
			wantPasswordSource: keepassPasswordSourcePrompt,
			wantTimeout:        90 * time.Second,
		},
		{
			name: "normalizes legacy Keychain source",
			yaml: `keepass_db: /tmp/passwords.kdbx
keepass_password:
  source: legacy_keychain
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
`,
			wantSource:         totpSourceKeePass,
			wantPasswordSource: keepassPasswordSourceKeychain,
			wantTimeout:        defaultLoginTimeout,
		},
		{
			name: "rejects invalid password source",
			yaml: `keepass_db: /tmp/passwords.kdbx
keepass_password:
  source: environment
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
`,
			wantError: "keepass_password.source must be",
		},
		{
			name: "rejects unknown field",
			yaml: `keepass_db: /tmp/passwords.kdbx
unknown: true
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
`,
			wantError: "field unknown not found",
		},
		{
			name: "rejects invalid TOTP source",
			yaml: `keepass_db: /tmp/passwords.kdbx
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
    totp_source: magic
`,
			wantError: "totp_source must be",
		},
		{
			name: "rejects explicit zero timeout",
			yaml: `keepass_db: /tmp/passwords.kdbx
login_timeout: 0s
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
`,
			wantError: "login_timeout must be greater than zero",
		},
		{
			name: "rejects relative executable path",
			yaml: `keepass_db: /tmp/passwords.kdbx
tsh_path: bin/tsh
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
`,
			wantError: "tsh_path must be an absolute path",
		},
		{
			name: "rejects multiple documents",
			yaml: `keepass_db: /tmp/passwords.kdbx
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: Teleport/production
---
keepass_db: /tmp/other.kdbx
`,
			wantError: "multiple YAML documents",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), configFileName)
			if err := os.WriteFile(path, []byte(test.yaml), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg, err := loadConfig(path)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("loadConfig() error = %v, want substring %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig() error = %v", err)
			}
			if got := cfg.Teleports[0].TOTPSource; got != test.wantSource {
				t.Errorf("TOTPSource = %q, want %q", got, test.wantSource)
			}
			if got := cfg.KeePassPassword.Source; got != test.wantPasswordSource {
				t.Errorf("KeePassPassword.Source = %q, want %q", got, test.wantPasswordSource)
			}
			if got := cfg.loginTimeout(); got != test.wantTimeout {
				t.Errorf("loginTimeout() = %v, want %v", got, test.wantTimeout)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("config permissions = %o, want 600", got)
			}
		})
	}
}

func TestEnsurePrivateDirRejectsSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := ensurePrivateDir(link)
	if err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("ensurePrivateDir() error = %v, want symlink rejection", err)
	}
}

func TestWriteFileExclusive(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	destination := filepath.Join(directory, "destination.yaml")

	if err := writeFileExclusive(destination, []byte("content")); err != nil {
		t.Fatalf("writeFileExclusive() error = %v", err)
	}
	content, err := os.ReadFile(destination) // #nosec G304 -- destination is inside t.TempDir and created by the test.
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "content" {
		t.Fatalf("destination content = %q, want content", content)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("destination permissions = %o, want 600", got)
	}
	if err := writeFileExclusive(destination, []byte("replacement")); err == nil {
		t.Fatal("second write succeeded, want exclusive-create error")
	}
}
