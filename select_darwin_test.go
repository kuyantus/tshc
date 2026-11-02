//go:build darwin && integration

package main

import (
	"bytes"
	"context"
	"os"
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
	for _, source := range []string{"environment", "options file"} {
		t.Run(source, func(t *testing.T) {
			// Keep user styling while overriding options that change the selection format.
			const options = "--filter=tshc-integration-fixture --multi --print-query --read0 --print0 --expect=enter --layout=reverse --accept-nth=2.."
			t.Setenv("FZF_DEFAULT_OPTS", options)
			t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
			if source == "options file" {
				optionsPath := filepath.Join(t.TempDir(), "fzf-options")
				if err := os.WriteFile(optionsPath, []byte(options), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("FZF_DEFAULT_OPTS", "")
				t.Setenv("FZF_DEFAULT_OPTS_FILE", optionsPath)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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
		})
	}
	t.Logf("selected synthetic fixture with installed Homebrew fzf: %s", path)
}
