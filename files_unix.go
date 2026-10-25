//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func fileOwnerUID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("file ownership information is unavailable")
	}
	return stat.Uid, nil
}

func fileGroupID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("file group information is unavailable")
	}
	return stat.Gid, nil
}

func effectiveUID() int {
	return os.Geteuid()
}

func openRegularFile(path string) (*os.File, error) {
	return openValidatedFile(path, unix.O_RDONLY, false)
}

func openRegularNoFollow(path string) (*os.File, error) {
	return openValidatedFile(path, unix.O_RDONLY|unix.O_NOFOLLOW, false)
}

func openDirectoryNoFollow(path string) (*os.File, error) {
	return openValidatedFile(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, true)
}

func openValidatedFile(path string, flags int, wantDirectory bool) (*os.File, error) {
	// A FIFO must reach the type check without waiting for a writer.
	descriptor, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("create file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	validType := info.Mode().IsRegular()
	if wantDirectory {
		validType = info.IsDir()
	}
	if !validType {
		_ = file.Close()
		expected := "regular file"
		if wantDirectory {
			expected = "directory"
		}
		return nil, fmt.Errorf("must be a %s, not a special file", expected)
	}
	return file, nil
}
