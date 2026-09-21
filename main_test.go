package main

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestRunCLIHelpAndVersion(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		args     []string
		wantCode int
		wantText string
	}{
		{name: "help", args: []string{"--help"}, wantCode: 0, wantText: "Usage: tshc"},
		{name: "version", args: []string{"--version"}, wantCode: 0, wantText: version},
		{name: "unknown flag", args: []string{"--unknown"}, wantCode: 2, wantText: "flag provided but not defined"},
		{name: "positional argument", args: []string{"cluster"}, wantCode: 2, wantText: "unexpected arguments"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			var errorOutput bytes.Buffer
			code := runCLI(context.Background(), test.args, nil, &output, &errorOutput)
			if code != test.wantCode {
				t.Fatalf("runCLI() = %d, want %d", code, test.wantCode)
			}
			if combined := output.String() + errorOutput.String(); !bytes.Contains([]byte(combined), []byte(test.wantText)) {
				t.Errorf("output = %q, want substring %q", combined, test.wantText)
			}
		})
	}
}

func TestRunCLIKeychainHelp(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	code := runCLI(context.Background(), []string{"keychain", "help"}, nil, &output, &errorOutput)
	if code != 0 {
		t.Fatalf("runCLI(keychain help) = %d, want 0", code)
	}
	if !bytes.Contains(errorOutput.Bytes(), []byte("tshc keychain set")) {
		t.Errorf("error output = %q, want keychain usage", errorOutput.String())
	}
}

func TestSignalExitCode(t *testing.T) {
	t.Parallel()

	if got := signalExitCode(signalCause{signal: syscall.SIGINT}); got != 130 {
		t.Errorf("SIGINT exit code = %d, want 130", got)
	}
	if got := signalExitCode(signalCause{signal: syscall.SIGTERM}); got != 143 {
		t.Errorf("SIGTERM exit code = %d, want 143", got)
	}
}

func TestSignalContextStopIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx, stop := signalContext(context.Background())
	stop()
	stop()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatalf("context cause = %v, want context canceled", context.Cause(ctx))
	}
}

func TestSignalCauseError(t *testing.T) {
	t.Parallel()

	if got := (signalCause{signal: syscall.SIGTERM}).Error(); got != syscall.SIGTERM.String() {
		t.Errorf("Error() = %q, want %q", got, syscall.SIGTERM.String())
	}
}
