package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

const (
	keychainCommand = "/usr/bin/security"
	keychainService = "teleport-login"
	keychainAccount = "keepass"
)

type securityOperation uint8

const (
	securityOperationSet securityOperation = iota + 1
	securityOperationDelete
)

type securityCommandRunner func(
	context.Context,
	securityOperation,
	io.Reader,
	io.Writer,
	io.Writer,
) error

type keychainManager struct {
	platform    string
	input       io.Reader
	output      io.Writer
	errorOutput io.Writer
	runCommand  securityCommandRunner
}

func runKeychainCLI(
	ctx context.Context,
	args []string,
	input *os.File,
	output io.Writer,
	errorOutput io.Writer,
) int {
	manager := keychainManager{
		platform:    runtime.GOOS,
		input:       input,
		output:      output,
		errorOutput: errorOutput,
		runCommand:  runSecurityCommand,
	}
	if err := manager.run(ctx, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if ctx.Err() != nil {
			return signalExitCode(context.Cause(ctx))
		}
		_, _ = fmt.Fprintln(errorOutput, "ERROR:", err)
		return 1
	}
	return 0
}

func (m keychainManager) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		m.printUsage()
		return errors.New("missing keychain command")
	}

	switch args[0] {
	case "set":
		if err := parseNoArgs("keychain set", args[1:], m.errorOutput); err != nil {
			return err
		}
		return m.set(ctx)
	case "delete":
		if err := parseNoArgs("keychain delete", args[1:], m.errorOutput); err != nil {
			return err
		}
		return m.delete(ctx)
	case "help", "-h", "--help":
		m.printUsage()
		return nil
	default:
		m.printUsage()
		return fmt.Errorf("unknown keychain command %q", args[0])
	}
}

func parseNoArgs(command string, args []string, output io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(output, "Usage: tshc "+command)
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%s: unexpected arguments: %v", command, flags.Args())
	}
	return nil
}

func (m keychainManager) set(ctx context.Context) error {
	if err := m.requireMacOS(); err != nil {
		return err
	}

	if err := m.runCommand(ctx, securityOperationSet, m.input, m.output, m.errorOutput); err != nil {
		return fmt.Errorf("store KeePass password in macOS Keychain: %w", err)
	}
	_, err := fmt.Fprintln(m.output, "Stored the KeePass password in macOS Keychain.")
	return err
}

func (m keychainManager) delete(ctx context.Context) error {
	if err := m.requireMacOS(); err != nil {
		return err
	}

	if err := m.runCommand(ctx, securityOperationDelete, m.input, m.output, m.errorOutput); err != nil {
		return fmt.Errorf("delete KeePass password from macOS Keychain: %w", err)
	}
	_, err := fmt.Fprintln(m.output, "Deleted the KeePass password from macOS Keychain.")
	return err
}

func (m keychainManager) requireMacOS() error {
	if m.platform != "darwin" {
		return errors.New("macOS Keychain commands are available only on macOS")
	}
	return nil
}

func (m keychainManager) printUsage() {
	_, _ = fmt.Fprintln(m.errorOutput, `Usage:
  tshc keychain set
  tshc keychain delete`)
}

func runSecurityCommand(
	ctx context.Context,
	operation securityOperation,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) error {
	command, err := newSecurityCommand(ctx, operation)
	if err != nil {
		return err
	}
	command.Stdin = input
	command.Stdout = output
	command.Stderr = errorOutput
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

func newSecurityCommand(ctx context.Context, operation securityOperation) (*exec.Cmd, error) {
	switch operation {
	case securityOperationSet:
		// Do not trust the shared security executable to read a new item silently.
		// -U preserves existing trusted applications, including Always Allow.
		// The security tool prompts because -w is the final argument. Supplying
		// the password as an argument would expose it through the process list.
		return exec.CommandContext(
			ctx,
			keychainCommand,
			"add-generic-password",
			"-U",
			"-s", keychainService,
			"-a", keychainAccount,
			"-T", "",
			"-w",
		), nil
	case securityOperationDelete:
		return exec.CommandContext(
			ctx,
			keychainCommand,
			"delete-generic-password",
			"-s", keychainService,
			"-a", keychainAccount,
		), nil
	default:
		return nil, fmt.Errorf("unsupported security operation %d", operation)
	}
}
