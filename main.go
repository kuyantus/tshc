// Package main implements the tshc Teleport login helper.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
)

var version = "dev"

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, stop := signalContext(context.Background())
	defer stop()
	return runCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}

func runCLI(ctx context.Context, args []string, input *os.File, output, errorOutput io.Writer) int {
	if len(args) > 0 && args[0] == "keychain" {
		return runKeychainCLI(ctx, args[1:], input, output, errorOutput)
	}

	flags := flag.NewFlagSet("tshc", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	showVersion := flags.Bool("version", false, "print version and exit")
	flags.Usage = func() {
		_, _ = fmt.Fprintf(flags.Output(), "Usage: tshc [--version]\n       tshc keychain <command>\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(errorOutput, "ERROR: unexpected arguments: %v\n", flags.Args())
		flags.Usage()
		return 2
	}
	if *showVersion {
		if _, err := fmt.Fprintln(output, reportedVersion()); err != nil {
			return 1
		}
		return 0
	}

	if err := run(ctx, input, output, errorOutput); err != nil {
		if ctx.Err() != nil {
			return signalExitCode(context.Cause(ctx))
		}
		_, _ = fmt.Fprintln(errorOutput, "ERROR:", err)
		return 1
	}

	return 0
}

func reportedVersion() string {
	info, _ := debug.ReadBuildInfo()
	return versionForBuild(version, info)
}

func versionForBuild(stamped string, info *debug.BuildInfo) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

type signalCause struct {
	signal os.Signal
}

func (e signalCause) Error() string {
	return e.signal.String()
}

func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		select {
		case received := <-signals:
			signal.Stop(signals)
			cancel(signalCause{signal: received})
		case <-done:
		}
	}()

	var stopOnce sync.Once
	return ctx, func() {
		stopOnce.Do(func() {
			signal.Stop(signals)
			close(done)
			cancel(context.Canceled)
		})
	}
}

func signalExitCode(cause error) int {
	if interrupted, ok := errors.AsType[signalCause](cause); ok {
		switch interrupted.signal {
		case os.Interrupt:
			return 130
		case syscall.SIGTERM:
			return 143
		}
	}
	return 1
}
