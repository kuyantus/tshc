package main

import (
	"os/user"
	"runtime"
	"strconv"
	"strings"
)

func isTrustedHomebrewParent(path, directory string, groupID uint32) bool {
	if !isHomebrewParent(runtime.GOOS, path, directory) {
		return false
	}
	// macOS Homebrew uses admin-writable directories. Treat administrators
	// managing the standard installation as trusted, just like its owner.
	group, err := user.LookupGroup("admin")
	return err == nil && group.Gid == strconv.FormatUint(uint64(groupID), 10)
}

func isHomebrewParent(goos, path, directory string) bool {
	if goos != "darwin" || !strings.HasPrefix(path, directory+"/") {
		return false
	}
	for _, prefix := range []string{"/opt/homebrew", "/usr/local"} {
		cellar := prefix + "/Cellar"
		if strings.HasPrefix(path, cellar+"/") &&
			(directory == prefix || directory == cellar || strings.HasPrefix(directory, cellar+"/")) {
			return true
		}
	}
	return false
}
