package main

import (
	"os/user"
	"runtime"
	"strconv"
	"testing"
)

func TestTrustedAdministratorGroup(t *testing.T) {
	t.Parallel()
	if isTrustedAdministratorGroup(4294967295) {
		t.Fatal("trusted an unrelated group")
	}
	if runtime.GOOS != "darwin" {
		if isTrustedAdministratorGroup(80) {
			t.Fatal("applied macOS administrator trust on another operating system")
		}
		return
	}
	for _, name := range []string{"admin", "staff", "wheel"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			group, err := user.LookupGroup(name)
			if err != nil {
				t.Fatal(err)
			}
			id, err := strconv.ParseUint(group.Gid, 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			if got := isTrustedAdministratorGroup(uint32(id)); got != (name == "admin") {
				t.Errorf("trust for %s = %v", name, got)
			}
		})
	}
}
