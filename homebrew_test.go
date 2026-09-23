package main

import (
	"testing"
)

func TestHomebrewParentBoundaries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		goos      string
		path      string
		directory string
		want      bool
	}{
		{name: "Apple Silicon Cellar", goos: "darwin", path: "/opt/homebrew/Cellar/fzf/1/bin/fzf", directory: "/opt/homebrew/Cellar", want: true},
		{name: "Apple Silicon prefix", goos: "darwin", path: "/opt/homebrew/Cellar/fzf/1/bin/fzf", directory: "/opt/homebrew", want: true},
		{name: "Intel Cellar", goos: "darwin", path: "/usr/local/Cellar/tsh/1/bin/tsh", directory: "/usr/local/Cellar", want: true},
		{name: "package ancestor", goos: "darwin", path: "/opt/homebrew/Cellar/fzf/1/bin/fzf", directory: "/opt/homebrew/Cellar/fzf/1", want: true},
		{name: "outside Homebrew prefix", goos: "darwin", path: "/opt/homebrew/Cellar/fzf/1/bin/fzf", directory: "/opt"},
		{name: "unrelated package", goos: "darwin", path: "/opt/homebrew/Cellar/fzf/1/bin/fzf", directory: "/opt/homebrew/Cellar/other"},
		{name: "lookalike prefix", goos: "darwin", path: "/opt/homebrew-other/Cellar/fzf/1/bin/fzf", directory: "/opt/homebrew-other/Cellar"},
		{name: "lookalike Cellar", goos: "darwin", path: "/opt/homebrew/Cellar-other/fzf/1/bin/fzf", directory: "/opt/homebrew"},
		{name: "arbitrary local binary", goos: "darwin", path: "/usr/local/bin/fzf", directory: "/usr/local"},
		{name: "Linux has no implicit admin trust", goos: "linux", path: "/opt/homebrew/Cellar/fzf/1/bin/fzf", directory: "/opt/homebrew/Cellar"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := isHomebrewParent(test.goos, test.path, test.directory); got != test.want {
				t.Errorf("isHomebrewParent() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestHomebrewDoesNotTrustUnrelatedGroup(t *testing.T) {
	t.Parallel()
	if isTrustedHomebrewParent("/opt/homebrew/Cellar/fzf/1/bin/fzf", "/opt/homebrew/Cellar", 4294967295) {
		t.Fatal("accepted a non-admin group for Homebrew")
	}
}
