package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestKeychainManagerSetUsesSecurePasswordPrompt(t *testing.T) {
	t.Parallel()

	input := strings.NewReader("")
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	var gotOperation securityOperation
	manager := keychainManager{
		platform:    "darwin",
		input:       input,
		output:      &output,
		errorOutput: &errorOutput,
		runCommand: func(
			_ context.Context,
			operation securityOperation,
			gotInput io.Reader,
			gotOutput io.Writer,
			gotErrorOutput io.Writer,
		) error {
			gotOperation = operation
			if gotInput != input || gotOutput != &output || gotErrorOutput != &errorOutput {
				t.Error("set() did not connect the security command directly to the configured terminal streams")
			}
			return nil
		},
	}

	if err := manager.set(context.Background()); err != nil {
		t.Fatalf("set() error = %v", err)
	}
	if gotOperation != securityOperationSet {
		t.Fatalf("security operation = %d, want set", gotOperation)
	}
	if !strings.Contains(output.String(), "Stored") {
		t.Errorf("output = %q, want success message", output.String())
	}
}

func TestKeychainManagerSetWrapsCommandError(t *testing.T) {
	t.Parallel()

	commandErr := errors.New("security failed")
	manager := keychainManager{
		platform:    "darwin",
		output:      io.Discard,
		errorOutput: io.Discard,
		runCommand: func(context.Context, securityOperation, io.Reader, io.Writer, io.Writer) error {
			return commandErr
		},
	}
	if err := manager.set(context.Background()); !errors.Is(err, commandErr) {
		t.Fatalf("set() error = %v, want wrapped command error", err)
	}
}

func TestKeychainManagerDelete(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var gotOperation securityOperation
	manager := keychainManager{
		platform:    "darwin",
		output:      &output,
		errorOutput: io.Discard,
		runCommand: func(_ context.Context, operation securityOperation, _ io.Reader, _ io.Writer, _ io.Writer) error {
			gotOperation = operation
			return nil
		},
	}
	if err := manager.delete(context.Background()); err != nil {
		t.Fatalf("delete() error = %v", err)
	}
	if gotOperation != securityOperationDelete {
		t.Fatalf("security operation = %d, want delete", gotOperation)
	}
	if !strings.Contains(output.String(), "Deleted") {
		t.Errorf("output = %q, want success message", output.String())
	}
}

func TestKeychainManagerCommandDispatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		platform  string
		args      []string
		wantRuns  int
		wantError string
	}{
		{name: "help", platform: "linux", args: []string{"help"}},
		{name: "set", platform: "darwin", args: []string{"set"}, wantRuns: 1},
		{name: "delete", platform: "darwin", args: []string{"delete"}, wantRuns: 1},
		{name: "set on Linux", platform: "linux", args: []string{"set"}, wantError: "only on macOS"},
		{name: "missing command", platform: "darwin", wantError: "missing"},
		{name: "unknown command", platform: "darwin", args: []string{"unknown"}, wantError: "unknown"},
		{name: "set argument", platform: "darwin", args: []string{"set", "unexpected"}, wantError: "unexpected"},
		{name: "delete argument", platform: "darwin", args: []string{"delete", "unexpected"}, wantError: "unexpected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runs := 0
			manager := keychainManager{
				platform:    test.platform,
				output:      io.Discard,
				errorOutput: io.Discard,
				runCommand: func(context.Context, securityOperation, io.Reader, io.Writer, io.Writer) error {
					runs++
					return nil
				},
			}
			err := manager.run(context.Background(), test.args)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("run() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("run() error = %v, want substring %q", err, test.wantError)
			}
			if runs != test.wantRuns {
				t.Errorf("security command runs = %d, want %d", runs, test.wantRuns)
			}
		})
	}
}

func TestNewSecurityCommandUsesFixedArguments(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		operation securityOperation
		wantArgs  []string
	}{
		{
			name:      "set",
			operation: securityOperationSet,
			wantArgs: []string{
				keychainCommand,
				"add-generic-password",
				"-U",
				"-s", keychainService,
				"-a", keychainAccount,
				"-T", "",
				"-w",
			},
		},
		{
			name:      "delete",
			operation: securityOperationDelete,
			wantArgs: []string{
				keychainCommand,
				"delete-generic-password",
				"-s", keychainService,
				"-a", keychainAccount,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			command, err := newSecurityCommand(context.Background(), test.operation)
			if err != nil {
				t.Fatalf("newSecurityCommand() error = %v", err)
			}
			if !slices.Equal(command.Args, test.wantArgs) {
				t.Fatalf("security arguments = %q, want %q", command.Args, test.wantArgs)
			}
		})
	}

	if _, err := newSecurityCommand(context.Background(), 255); err == nil {
		t.Fatal("newSecurityCommand() accepted an unsupported operation")
	}
}
