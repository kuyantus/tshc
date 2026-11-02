package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
)

func BenchmarkOpenKeePass(b *testing.B) {
	for _, count := range []int{10, 1000} {
		b.Run(fmt.Sprintf("entries=%d", count), func(b *testing.B) {
			path := benchmarkKeePassFile(b, count)
			password := []byte("benchmark-master-password")
			defer clear(password)
			b.ReportAllocs()
			var retainedXML int
			for b.Loop() {
				database, err := openKeePass(path, password)
				if err != nil {
					b.Fatal(err)
				}
				if err := database.LockProtectedEntries(); err != nil {
					b.Fatal(err)
				}
				retainedXML = len(database.Content.RawData)
			}
			b.ReportMetric(float64(retainedXML), "retained-xml-B")
		})
	}
}

func benchmarkKeePassFile(b *testing.B, count int) string {
	b.Helper()
	// Keep the library's KDBX3 AES-KDF defaults unchanged: 6,000 rounds.
	database := benchmarkDatabase(count)
	database.Credentials = gokeepasslib.NewPasswordCredentials("benchmark-master-password")
	if err := database.LockProtectedEntries(); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "fixture.kdbx")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixture is under b.TempDir.
	if err != nil {
		b.Fatal(err)
	}
	encodeErr := gokeepasslib.NewEncoder(file).Encode(database)
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		b.Fatalf("encode fixture: %v; close: %v", encodeErr, closeErr)
	}
	return path
}

func BenchmarkParseTOTPSettings(b *testing.B) {
	for _, test := range []struct {
		name string
		uri  string
	}{
		{"defaults", "otpauth://totp/Teleport:alice?secret=JBSWY3DPEHPK3PXP"},
		{"custom", "otpauth://totp/Teleport:alice?secret=JBSWY3DPEHPK3PXP&issuer=Teleport&period=45&digits=8&algorithm=SHA256"},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				settings, err := parseTOTPSettings(test.uri)
				if err != nil {
					b.Fatal(err)
				}
				settings.clear()
			}
		})
	}
}
