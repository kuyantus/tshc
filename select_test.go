package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		choice    string
		count     int
		wantAll   bool
		wantIndex int
		wantError bool
	}{
		{name: "all", choice: "0\t[ALL] Login to all clusters\n", count: 2, wantAll: true},
		{name: "second", choice: "2\tproduction (example.com)\n", count: 2, wantIndex: 1},
		{name: "invalid format", choice: "production", count: 2, wantError: true},
		{name: "out of range", choice: "3\tproduction", count: 2, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSelection(test.choice, test.count)
			if test.wantError {
				if err == nil {
					t.Fatal("parseSelection() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSelection() error = %v", err)
			}
			if got.all != test.wantAll || got.index != test.wantIndex {
				t.Errorf("parseSelection() = %+v, want all=%v index=%d", got, test.wantAll, test.wantIndex)
			}
		})
	}
}

func TestSelectTeleportIncludesFZFError(t *testing.T) {
	t.Parallel()

	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatalf("get test executable: %v", err)
	}

	_, err = selectTeleport(context.Background(), testExecutable, []teleport{{Name: "test", Proxy: "example.com"}})
	if err == nil {
		t.Fatal("selectTeleport() succeeded, want fzf error")
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("selectTeleport() error = %v, want exec.ExitError", err)
	}
	detail := strings.TrimSpace(string(exitError.Stderr))
	if detail == "" || !strings.Contains(err.Error(), detail) {
		t.Fatalf("selectTeleport() error = %v, want captured stderr %q", err, detail)
	}
}
