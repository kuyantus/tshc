//go:build darwin && integration

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestApplicationWithInstalledExecutables(t *testing.T) {
	for _, name := range []string{"fzf", "tsh"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s is not installed", name)
		}
		t.Logf("installed %s: %s", name, path)
	}
	home := trustedTempDir(t)
	configDirectory := filepath.Join(home, configDirName)
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configYAML := "keepass_db: unused.kdbx\nkeepass_password:\n  source: prompt\nteleports:\n" +
		"  - name: tshc-integration-fixture\n    proxy: fixture.invalid\n    keepass_entry: unused\n"
	if err := os.WriteFile(filepath.Join(configDirectory, configFileName), []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("FZF_DEFAULT_OPTS", "--filter=tshc-integration-fixture")
	t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
	stopBeforeSecrets := errors.New("stop before reading credentials")
	app := application{
		output:      io.Discard,
		errorOutput: io.Discard,
		readKeePassPassword: func(context.Context, keepassPasswordSource, secretInput, io.Writer) ([]byte, error) {
			return nil, stopBeforeSecrets
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.run(ctx); !errors.Is(err, stopBeforeSecrets) {
		t.Fatalf("run() error = %v, want installed fzf and tsh accepted without extra config", err)
	}
}
