//go:build darwin

package main

import "golang.org/x/sys/unix"

func disableTerminalEcho(descriptor int) (func() error, error) {
	state, err := unix.IoctlGetTermios(descriptor, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	original := *state
	state.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(descriptor, unix.TIOCSETA, state); err != nil {
		return nil, err
	}
	return func() error {
		return unix.IoctlSetTermios(descriptor, unix.TIOCSETA, &original)
	}, nil
}
