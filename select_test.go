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
	"strconv"
	"strings"
	"syscall"
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

func TestSelectTeleportFallsBackForInsecureDiscoveredFZF(t *testing.T) {
	for _, name := range []string{"writable file", "writable Homebrew ancestor"} {
		t.Run(name, func(t *testing.T) {
			root := trustedTempDir(t)
			cellar := filepath.Join(root, "Cellar")
			binDirectory := filepath.Join(cellar, "fzf", "version", "bin")
			if err := os.MkdirAll(binDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "fzf-was-executed")
			fzfPath := filepath.Join(binDirectory, "fzf")
			script := fmt.Sprintf("#!/bin/sh\nprintf ran > %q\nprintf '1\\tfixture\\n'\n", marker)
			if err := writeTestExecutable(fzfPath, script); err != nil {
				t.Fatal(err)
			}
			if name == "writable file" {
				if err := os.Chmod(fzfPath, 0o720); err != nil { // #nosec G302 -- intentionally insecure fixture.
					t.Fatal(err)
				}
			} else if err := os.Chmod(cellar, 0o775); err != nil { // #nosec G302 -- reproduces Homebrew permissions.
				t.Fatal(err)
			}
			t.Setenv("PATH", binDirectory)

			teleports := []teleport{{Name: "first"}, {Name: "second"}}
			var output bytes.Buffer
			got, err := selectTeleport(context.Background(), selectionInput(t, "2\n"), &output, "", teleports)
			if err != nil {
				t.Fatalf("selectTeleport() error = %v, want basic selector", err)
			}
			if got.all || got.index != 1 {
				t.Errorf("selection = %+v, want second cluster", got)
			}
			if !strings.Contains(output.String(), "using basic selector") ||
				!strings.Contains(output.String(), "group- or world-writable") {
				t.Errorf("output = %q, want fallback reason", output.String())
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected fzf was executed: marker stat error = %v", err)
			}

			output.Reset()
			_, err = selectTeleport(context.Background(), nil, &output, fzfPath, teleports)
			if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
				t.Fatalf("explicit fzf error = %v, want unsafe configured path rejected", err)
			}
			if output.Len() != 0 {
				t.Errorf("output = %q, want no fallback for explicitly configured fzf", output.String())
			}
		})
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

func TestSelectTeleportWithFZFBoundsInheritedPipes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		cancel    bool
		scriptEnd string
		wantError error
	}{
		{name: "canceled selector", cancel: true, scriptEnd: "wait\n", wantError: context.Canceled},
		{name: "exited selector", scriptEnd: "printf '1\\tfixture\\n'\n", wantError: exec.ErrWaitDelay},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "fzf")
			script := "#!/bin/sh\nsleep 5 &\nprintf '%s\\n' \"$!\" > \"$0.pid\"\n" + test.scriptEnd
			if err := writeTestExecutable(path, script); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				data, err := os.ReadFile(path + ".pid") // #nosec G304 -- path is an executable fixture under t.TempDir.
				if errors.Is(err, os.ErrNotExist) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
				if err != nil || pid <= 0 {
					t.Errorf("invalid fixture child PID %q", data)
					return
				}
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					t.Errorf("stop fixture child: %v", err)
				}
			})

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if test.cancel {
				go func() {
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					for {
						if _, err := os.Stat(path + ".pid"); err == nil {
							cancel()
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
						}
					}
				}()
			}
			started := time.Now()
			_, err := selectTeleportWithFZF(ctx, path, []teleport{{Name: "fixture", Proxy: "fixture.invalid"}})
			if !errors.Is(err, test.wantError) {
				t.Errorf("selectTeleportWithFZF() error = %v, want %v", err, test.wantError)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Errorf("selectTeleportWithFZF() took %v with an inherited output pipe", elapsed)
			}
		})
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
		{name: "CRLF line ending", choice: "2\tproduction (example.com)\r\n", count: 2, wantIndex: 1},
		{name: "invalid format", choice: "production", count: 2, wantError: true},
		{name: "out of range", choice: "3\tproduction", count: 2, wantError: true},
		{name: "multiple selections", choice: "1\tproduction\n2\tstaging\n", count: 2, wantError: true},
		{name: "query prefix", choice: "query\n1\tproduction\n", count: 2, wantError: true},
		{name: "expected key prefix", choice: "enter\n1\tproduction\n", count: 2, wantError: true},
		{name: "blank prefix", choice: "\n1\tproduction\n", count: 2, wantError: true},
		{name: "extra blank line", choice: "1\tproduction\n\n", count: 2, wantError: true},
		{name: "NUL record ending", choice: "1\tproduction\x00", count: 2, wantError: true},
		{name: "NUL separated selections", choice: "1\tproduction\x002\tstaging\x00", count: 2, wantError: true},
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
