//go:build integration

package main

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSelectTeleportWithLegacyFZF(t *testing.T) {
	path := os.Getenv("TSHC_TEST_LEGACY_FZF")
	if path == "" {
		t.Skip("set TSHC_TEST_LEGACY_FZF to an fzf executable older than 0.60")
	}
	t.Setenv("FZF_DEFAULT_OPTS", "--filter=tshc-integration-fixture --layout=reverse")
	t.Setenv("FZF_DEFAULT_OPTS_FILE", "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := selectTeleportWithFZF(ctx, path, []teleport{
		{Name: "tshc-integration-fixture", Proxy: "fixture.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.all || got.index != 0 {
		t.Fatalf("selection = %+v, want first cluster", got)
	}
}
