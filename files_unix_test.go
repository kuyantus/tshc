//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenRegularNoFollowRejectsFIFO(t *testing.T) {
	t.Parallel()

	assertFIFORejected(t, func(path string) error {
		file, err := openRegularNoFollow(path)
		if file != nil {
			_ = file.Close()
		}
		return err
	})
}

func assertFIFORejected(t *testing.T, open func(string) error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "pipe")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- open(path) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a FIFO, want regular-file error")
		}
	case <-time.After(time.Second):
		// Release a blocking open so a failed regression test leaves no goroutine.
		writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0) // #nosec G304 -- path is the FIFO fixture under t.TempDir.
		if err != nil {
			t.Fatalf("open blocked on FIFO; unblock writer: %v", err)
		}
		_ = writer.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("accepted a FIFO after unblocking it")
			}
		case <-time.After(time.Second):
			t.Fatal("open remained blocked after FIFO writer closed")
		}
		t.Fatal("open blocked on FIFO instead of rejecting it")
	}
}
