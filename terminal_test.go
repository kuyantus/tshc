//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestTerminalSecretInputReadsLine(t *testing.T) {
	t.Parallel()

	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = terminal.Close()
	})

	restore, err := disableTerminalEcho(int(terminal.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restore() })

	writeErr := make(chan error, 1)
	go func() {
		_, err := master.Write([]byte("terminal-secret\n"))
		writeErr <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	secret, err := (terminalSecretInput{file: terminal}).ReadSecret(ctx)
	if err != nil {
		t.Fatalf("ReadSecret() error = %v", err)
	}
	defer clear(secret)
	if err := <-writeErr; err != nil {
		t.Fatalf("write PTY input: %v", err)
	}
	if got := string(secret); got != "terminal-secret" {
		t.Errorf("ReadSecret() = %q, want terminal-secret", got)
	}
}

func TestTerminalSecretInputHonorsCancellation(t *testing.T) {
	t.Parallel()

	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = terminal.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = (terminalSecretInput{file: terminal}).ReadSecret(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadSecret() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("ReadSecret() returned after %v", elapsed)
	}
}
