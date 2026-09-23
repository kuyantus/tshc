//go:build darwin && integration

package main

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelectTeleportWithHomebrewFZF(t *testing.T) {
	path, err := exec.LookPath("fzf")
	if err != nil {
		t.Skip("Homebrew fzf is not installed")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, "/Cellar/fzf/") {
		t.Skip("fzf in PATH is not a Homebrew installation")
	}
	// Filter mode exercises the installed selector without a TTY or user config.
	t.Setenv("FZF_DEFAULT_OPTS", "--filter=tshc-integration-fixture")
	t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	got, err := selectTeleport(ctx, nil, &output, path, []teleport{
		{Name: "tshc-integration-fixture", Proxy: "fixture.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.all || got.index != 0 || output.Len() != 0 {
		t.Fatalf("selection = %+v, output = %q; want fixture selected through fzf", got, output.String())
	}
	t.Logf("selected synthetic fixture with installed Homebrew fzf: %s", path)
}
