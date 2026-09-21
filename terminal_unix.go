//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

func waitForTerminalInput(ctx context.Context, descriptor int) error {
	if descriptor < 0 || descriptor > math.MaxInt32 {
		return fmt.Errorf("terminal descriptor %d is out of range", descriptor)
	}
	pollDescriptors := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := unix.Poll(pollDescriptors, int((100 * time.Millisecond).Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for terminal input: %w", err)
		}
		if ready == 0 {
			continue
		}
		events := pollDescriptors[0].Revents
		if events&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("terminal input became unavailable")
		}
		if events&(unix.POLLIN|unix.POLLHUP) != 0 {
			return nil
		}
	}
}
