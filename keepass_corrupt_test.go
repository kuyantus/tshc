package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
)

func TestOpenKeePassRejectsTruncatedDatabase(t *testing.T) {
	t.Parallel()

	database := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	database.Credentials = gokeepasslib.NewPasswordCredentials("fixture-master")
	database.Content.Root.Groups = []gokeepasslib.Group{{Entries: []gokeepasslib.Entry{keepassEntry("fixture-password")}}}
	var encoded bytes.Buffer
	if err := gokeepasslib.NewEncoder(&encoded).Encode(database); err != nil {
		t.Fatal(err)
	}

	for _, size := range []int{0, 1, 12, encoded.Len() / 2, encoded.Len() - 1, encoded.Len() - 16} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "truncated.kdbx")
			if err := os.WriteFile(path, encoded.Bytes()[:size], 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := openKeePass(path, []byte("fixture-master")); err == nil {
				t.Fatal("accepted a truncated KeePass database")
			}
		})
	}
}
