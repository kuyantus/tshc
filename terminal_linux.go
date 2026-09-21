//go:build linux

package main

import "golang.org/x/sys/unix"

func disableTerminalEcho(descriptor int) (func() error, error) {
	state, err := unix.IoctlGetTermios(descriptor, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	original := *state
	state.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(descriptor, unix.TCSETS, state); err != nil {
		return nil, err
	}
	return func() error {
		return unix.IoctlSetTermios(descriptor, unix.TCSETS, &original)
	}, nil
}
