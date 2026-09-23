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

func openRegularNoFollow(path string) (*os.File, error) {
	return openNoFollow(path, unix.O_RDONLY, false)
}

func openDirectoryNoFollow(path string) (*os.File, error) {
	return openNoFollow(path, unix.O_RDONLY|unix.O_DIRECTORY, true)
}

func openNoFollow(path string, flags int, wantDirectory bool) (*os.File, error) {
	descriptor, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
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
		return nil, fmt.Errorf("must be a %s, not a symlink or special file", expected)
	}
	return file, nil
}
