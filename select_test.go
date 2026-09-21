package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelectTeleportFallsBackWithoutFZF(t *testing.T) {
	emptyPath := trustedTempDir(t)
	t.Setenv("PATH", emptyPath)

	input := selectionInput(t, "invalid\n3\n2\n")
	teleports := []teleport{
		{Name: "production", Proxy: "teleport.example.com"},
		{Name: "staging", Proxy: "staging.teleport.example.com"},
	}
	var output bytes.Buffer
	got, err := selectTeleport(context.Background(), input, &output, "", teleports)
	if err != nil {
		t.Fatalf("selectTeleport() error = %v", err)
	}
	if got.all || got.index != 1 {
		t.Errorf("selectTeleport() = %+v, want second cluster", got)
	}
	wantOutput := "fzf not found; using basic selector."
	if !strings.Contains(output.String(), wantOutput) {
		t.Errorf("output = %q, want %q", output.String(), wantOutput)
	}
	if got := strings.Count(output.String(), "Invalid selection:"); got != 2 {
		t.Errorf("validation error count = %d, want 2; output = %q", got, output.String())
	}
}

func TestSelectTeleportDoesNotFallbackForConfiguredFZF(t *testing.T) {
	t.Parallel()

	configuredPath := filepath.Join(trustedTempDir(t), "missing-fzf")
	var output bytes.Buffer
	_, err := selectTeleport(context.Background(), nil, &output, configuredPath, []teleport{{Name: "test"}})
	if err == nil || !strings.Contains(err.Error(), "inspect fzf executable") {
		t.Fatalf("selectTeleport() error = %v, want configured-path error", err)
	}
	if output.Len() != 0 {
		t.Errorf("output = %q, want no fallback output", output.String())
	}
}

func TestSelectTeleportDoesNotFallbackForInsecureFZF(t *testing.T) {
	binDirectory := trustedTempDir(t)
	fzfPath := filepath.Join(binDirectory, "fzf")
	if err := writeTestExecutable(fzfPath, "#!/bin/sh\nexit 0\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fzfPath, 0o720); err != nil { // #nosec G302 -- intentionally insecure fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory)

	var output bytes.Buffer
	_, err := selectTeleport(context.Background(), nil, &output, "", []teleport{{Name: "test"}})
	if err == nil || !strings.Contains(err.Error(), "file is group- or world-writable") {
		t.Fatalf("selectTeleport() error = %v, want insecure executable error", err)
	}
	if output.Len() != 0 {
		t.Errorf("output = %q, want no fallback output", output.String())
	}
}

func TestSelectTeleportInTerminalCancel(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	_, err := selectTeleportInTerminal(
		context.Background(),
		selectionInput(t, ""),
		&output,
		[]teleport{{Name: "test", Proxy: "example.com"}},
	)
	if !errors.Is(err, errSelectionCanceled) {
		t.Fatalf("selectTeleportInTerminal() error = %v, want selection canceled", err)
	}
}

func TestSelectTeleportInTerminalHonorsCancellation(t *testing.T) {
	t.Parallel()

	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = writer.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	_, err = selectTeleportInTerminal(ctx, input, &output, []teleport{{Name: "test", Proxy: "example.com"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("selectTeleportInTerminal() error = %v, want deadline exceeded", err)
	}
}

func TestReadSelectionLineDoesNotConsumeFollowingInput(t *testing.T) {
	t.Parallel()

	input := selectionInput(t, "2\nnext-secret\n")
	got, err := readSelectionLine(context.Background(), input)
	if err != nil {
		t.Fatalf("readSelectionLine() error = %v", err)
	}
	if got != "2" {
		t.Errorf("readSelectionLine() = %q, want 2", got)
	}
	remaining, err := io.ReadAll(input)
	if err != nil {
		t.Fatalf("read remaining input: %v", err)
	}
	if got := string(remaining); got != "next-secret\n" {
		t.Errorf("remaining input = %q, want next input preserved", got)
	}
}

func TestReadSelectionLineDrainsOverlongLine(t *testing.T) {
	t.Parallel()

	input := selectionInput(t, strings.Repeat("1", maxSelectionInputBytes+1)+"\n2\n")
	_, err := readSelectionLine(context.Background(), input)
	if !errors.Is(err, errSelectionTooLong) {
		t.Fatalf("readSelectionLine() error = %v, want selection too long", err)
	}
	got, err := readSelectionLine(context.Background(), input)
	if err != nil {
		t.Fatalf("second readSelectionLine() error = %v", err)
	}
	if got != "2" {
		t.Errorf("second readSelectionLine() = %q, want 2", got)
	}
}

func TestParseTerminalSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		choice    string
		count     int
		wantAll   bool
		wantIndex int
		wantError bool
	}{
		{name: "all", choice: "0", count: 2, wantAll: true},
		{name: "second", choice: " 2 ", count: 2, wantIndex: 1},
		{name: "not a number", choice: "production", count: 2, wantError: true},
		{name: "negative", choice: "-1", count: 2, wantError: true},
		{name: "out of range", choice: "3", count: 2, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTerminalSelection(test.choice, test.count)
			if test.wantError {
				if err == nil {
					t.Fatal("parseTerminalSelection() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTerminalSelection() error = %v", err)
			}
			if got.all != test.wantAll || got.index != test.wantIndex {
				t.Errorf("parseTerminalSelection() = %+v, want all=%v index=%d", got, test.wantAll, test.wantIndex)
			}
		})
	}
}

func TestSelectTeleportWithFZFIncludesError(t *testing.T) {
	t.Parallel()

	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatalf("get test executable: %v", err)
	}

	_, err = selectTeleportWithFZF(context.Background(), testExecutable, []teleport{{Name: "test", Proxy: "example.com"}})
	if err == nil {
		t.Fatal("selectTeleportWithFZF() succeeded, want fzf error")
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("selectTeleportWithFZF() error = %v, want exec.ExitError", err)
	}
	detail := strings.TrimSpace(string(exitError.Stderr))
	if detail == "" || !strings.Contains(err.Error(), detail) {
		t.Fatalf("selectTeleportWithFZF() error = %v, want captured stderr %q", err, detail)
	}
}

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

func selectionInput(t *testing.T, content string) *os.File {
	t.Helper()

	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(writer, content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
	})
	return input
}
