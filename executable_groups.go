package main

import (
	"os/user"
	"runtime"
	"strconv"
)

func isTrustedAdministratorGroup(groupID uint32) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	// Administrators manage macOS software directories, including Homebrew's
	// Cellar and /Applications. They are part of the trusted system boundary.
	group, err := user.LookupGroup("admin")
	return err == nil && group.Gid == strconv.FormatUint(uint64(groupID), 10)
}
