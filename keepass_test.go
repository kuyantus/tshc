package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestParseTOTPSettings(t *testing.T) {
	t.Parallel()

	raw := "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=45&digits=8&algorithm=SHA256"
	settings, err := parseTOTPSettings(raw)
	if err != nil {
		t.Fatalf("parseTOTPSettings() error = %v", err)
	}
	t.Cleanup(settings.clear)

	if settings.period != 45 {
		t.Errorf("period = %d, want 45", settings.period)
	}
	if settings.digits != otp.DigitsEight {
		t.Errorf("digits = %v, want %v", settings.digits, otp.DigitsEight)
	}
	if settings.algorithm != otp.AlgorithmSHA256 {
		t.Errorf("algorithm = %v, want %v", settings.algorithm, otp.AlgorithmSHA256)
	}

	at := time.Unix(1_700_000_000, 0)
	want, err := totp.GenerateCodeCustom("JBSWY3DPEHPK3PXP", at, totp.ValidateOpts{
		Period: 45, Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA256, Encoder: otp.EncoderDefault,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := settings.generate(at)
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	if got != want {
		t.Errorf("generate() = %q, want %q", got, want)
	}
}

func TestParseTOTPSettingsRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "wrong type", raw: "otpauth://hotp/example?secret=JBSWY3DPEHPK3PXP"},
		{name: "missing secret", raw: "otpauth://totp/example?issuer=Example"},
		{name: "MD5", raw: "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"},
		{name: "unknown algorithm", raw: "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&algorithm=SHA3"},
		{name: "unsupported digits", raw: "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&digits=7"},
		{name: "excessive period", raw: "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&period=301"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseTOTPSettings(test.raw); err == nil {
				t.Fatalf("parseTOTPSettings(%q) succeeded, want error", test.raw)
			}
		})
	}
}

func TestParseTOTPSettingsDoesNotExposeSecret(t *testing.T) {
	t.Parallel()

	const secret = "SUPERSECRETTOTPSEED"
	_, err := parseTOTPSettings("https://example.com/?secret=" + secret)
	if err == nil {
		t.Fatal("parseTOTPSettings() succeeded, want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposes TOTP secret: %v", err)
	}
}

func TestClearDatabaseCredentials(t *testing.T) {
	t.Parallel()

	database := gokeepasslib.NewDatabase()
	database.Credentials = gokeepasslib.NewPasswordCredentials("secret")
	passphrase := database.Credentials.Passphrase
	clearDatabaseCredentials(database)
	if database.Credentials != nil {
		t.Fatal("database credentials were not released")
	}
	for _, value := range passphrase {
		if value != 0 {
			t.Fatal("database passphrase hash was not cleared")
		}
	}
}

func TestOpenKeePass(t *testing.T) {
	t.Parallel()

	const masterPassword = "correct horse battery staple"
	path := filepath.Join(t.TempDir(), "passwords.kdbx")
	entry := keepassEntry("teleport-password")
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "otp",
		Value: gokeepasslib.V{Content: "otpauth://totp/Teleport:alice?secret=JBSWY3DPEHPK3PXP"},
	})
	writeTestKeePassDatabase(t, path, masterPassword, entry)

	database, err := openKeePass(path, []byte(masterPassword))
	if err != nil {
		t.Fatalf("openKeePass() error = %v", err)
	}
	if database.Credentials != nil {
		t.Fatal("openKeePass() retained the database credentials")
	}
	opened, err := findEntry(database, "production")
	if err != nil {
		t.Fatalf("findEntry() error = %v", err)
	}
	if got := opened.GetContent("UserName"); got != "alice" {
		t.Errorf("UserName = %q, want alice", got)
	}
	if got := opened.GetPassword(); got != "teleport-password" {
		t.Errorf("Password = %q, want fixture password", got)
	}
	if err := database.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries() error = %v", err)
	}
}

func TestOpenKeePassRejectsWrongPasswordWithoutLeakingIt(t *testing.T) {
	t.Parallel()

	const wrongPassword = "definitely-wrong-and-secret"
	path := filepath.Join(t.TempDir(), "passwords.kdbx")
	writeTestKeePassDatabase(t, path, "right-password", keepassEntry("secret"))

	_, err := openKeePass(path, []byte(wrongPassword))
	if err == nil {
		t.Fatal("openKeePass() succeeded with a wrong password")
	}
	if strings.Contains(err.Error(), wrongPassword) {
		t.Fatalf("openKeePass() error exposes the password: %v", err)
	}
}

func TestParseKeychainPassword(t *testing.T) {
	t.Parallel()

	t.Run("trims command newline", func(t *testing.T) {
		t.Parallel()

		password, err := parseKeychainPassword([]byte("master-password\r\n"))
		if err != nil {
			t.Fatalf("parseKeychainPassword() error = %v", err)
		}
		defer clear(password)
		if got := string(password); got != "master-password" {
			t.Errorf("password = %q, want master-password", got)
		}
	})

	for _, test := range []struct {
		name   string
		output []byte
	}{
		{name: "empty", output: nil},
		{name: "newline only", output: []byte("\n")},
		{name: "too large", output: bytes.Repeat([]byte{'x'}, maxSecretLength+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseKeychainPassword(test.output); err == nil {
				t.Fatal("parseKeychainPassword() succeeded, want error")
			}
			for _, value := range test.output {
				if value != 0 {
					t.Fatal("parseKeychainPassword() did not clear rejected output")
				}
			}
		})
	}
}

func TestBoundedKeychainOutput(t *testing.T) {
	t.Parallel()

	var output boundedKeychainOutput
	data := bytes.Repeat([]byte{'x'}, maxSecretLength)
	if count, err := output.Write(data); count != len(data) || err != nil {
		t.Fatalf("Write(password) = (%d, %v)", count, err)
	}
	if count, err := output.Write([]byte("\r\n")); count != 2 || err != nil {
		t.Fatalf("Write(newline) = (%d, %v)", count, err)
	}
	if count, err := output.Write([]byte("extra")); count != 0 || !errors.Is(err, errKeychainOutputTooLarge) {
		t.Fatalf("Write(extra) = (%d, %v), want size error", count, err)
	}
	if !output.exceeded {
		t.Error("bounded output did not record overflow")
	}
	if len(output.data) != maxSecretLength+2 {
		t.Errorf("buffer length = %d, want %d", len(output.data), maxSecretLength+2)
	}
	clear(output.data)
}

func TestKeePassPasswordSource(t *testing.T) {
	t.Parallel()

	t.Run("uses macOS Keychain", func(t *testing.T) {
		t.Parallel()

		input := &staticSecretInput{err: errors.New("terminal input must not be used")}
		password, err := (keePassPasswordReader{
			platform: "darwin",
			source:   keepassPasswordSourceKeychain,
			keychain: func(context.Context) ([]byte, error) {
				return []byte("from-keychain"), nil
			},
			input:  input,
			output: io.Discard,
		}).read(context.Background())
		if err != nil {
			t.Fatalf("read() error = %v", err)
		}
		defer clear(password)
		if got := string(password); got != "from-keychain" {
			t.Errorf("password = %q, want Keychain value", got)
		}
	})

	t.Run("falls back to terminal", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		password, err := (keePassPasswordReader{
			platform: "darwin",
			source:   keepassPasswordSourceKeychain,
			keychain: func(context.Context) ([]byte, error) {
				return nil, errors.New("not found")
			},
			input:  &staticSecretInput{values: [][]byte{[]byte("from-terminal")}},
			output: &output,
		}).read(context.Background())
		if err != nil {
			t.Fatalf("read() error = %v", err)
		}
		defer clear(password)
		if got := string(password); got != "from-terminal" {
			t.Errorf("password = %q, want terminal value", got)
		}
		if got := output.String(); !strings.Contains(got, "KeePass password:") {
			t.Errorf("output = %q, want password prompt", got)
		}
	})

	t.Run("skips Keychain on other platforms", func(t *testing.T) {
		t.Parallel()

		keychainCalled := false
		password, err := (keePassPasswordReader{
			platform: "linux",
			source:   keepassPasswordSourceKeychain,
			keychain: func(context.Context) ([]byte, error) {
				keychainCalled = true
				return nil, nil
			},
			input:  &staticSecretInput{values: [][]byte{[]byte("from-terminal")}},
			output: io.Discard,
		}).read(context.Background())
		if err != nil {
			t.Fatalf("read() error = %v", err)
		}
		defer clear(password)
		if keychainCalled {
			t.Fatal("read() called macOS Keychain on Linux")
		}
	})

	t.Run("propagates cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := (keePassPasswordReader{
			platform: "darwin",
			source:   keepassPasswordSourceKeychain,
			keychain: func(context.Context) ([]byte, error) {
				return nil, context.Canceled
			},
			input:  &staticSecretInput{err: errors.New("terminal input must not be used")},
			output: io.Discard,
		}).read(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read() error = %v, want context canceled", err)
		}
	})

	t.Run("prompt source bypasses Keychain", func(t *testing.T) {
		t.Parallel()

		keychainCalled := false
		password, err := (keePassPasswordReader{
			platform: "darwin",
			source:   keepassPasswordSourcePrompt,
			keychain: func(context.Context) ([]byte, error) {
				keychainCalled = true
				return nil, nil
			},
			input:  &staticSecretInput{values: [][]byte{[]byte("manual-password")}},
			output: io.Discard,
		}).read(context.Background())
		if err != nil {
			t.Fatalf("read() error = %v", err)
		}
		defer clear(password)
		if keychainCalled {
			t.Fatal("prompt source accessed Keychain")
		}
	})

}

func TestGetKeePassPasswordPromptSource(t *testing.T) {
	t.Parallel()

	password, err := getKeePassPassword(
		context.Background(),
		keepassPasswordSourcePrompt,
		&staticSecretInput{values: [][]byte{[]byte("manual-password")}},
		io.Discard,
	)
	if err != nil {
		t.Fatalf("getKeePassPassword() error = %v", err)
	}
	defer clear(password)
	if got := string(password); got != "manual-password" {
		t.Errorf("password = %q, want manual-password", got)
	}
}

func TestFindEntry(t *testing.T) {
	t.Parallel()

	wanted := keepassEntry("secret")
	database := &gokeepasslib.Database{Content: &gokeepasslib.DBContent{Root: &gokeepasslib.RootData{
		Groups: []gokeepasslib.Group{{
			Name: "Root",
			Groups: []gokeepasslib.Group{{
				Name:    "Teleport",
				Entries: []gokeepasslib.Entry{wanted},
			}},
		}},
	}}}

	entry, err := findEntry(database, "Teleport/production")
	if err != nil {
		t.Fatalf("findEntry() error = %v", err)
	}
	if got := entry.GetContent("UserName"); got != "alice" {
		t.Errorf("UserName = %q, want alice", got)
	}
	if _, err := findEntry(database, "Teleport/missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing entry error = %v", err)
	}
	if _, err := findEntry(&gokeepasslib.Database{}, "entry"); err == nil {
		t.Fatal("empty database succeeded, want error")
	}
}

func keepassEntry(password string) gokeepasslib.Entry {
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "production"}},
		gokeepasslib.ValueData{Key: "UserName", Value: gokeepasslib.V{Content: "alice"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: password}},
	)
	return entry
}

func writeTestKeePassDatabase(t *testing.T, path, password string, entries ...gokeepasslib.Entry) {
	t.Helper()

	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = append(root.Entries, entries...)
	database := gokeepasslib.NewDatabase()
	database.Credentials = gokeepasslib.NewPasswordCredentials(password)
	database.Content.Root.Groups = []gokeepasslib.Group{root}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- caller supplies a path under t.TempDir.
	if err != nil {
		t.Fatalf("create KeePass fixture: %v", err)
	}
	encodeErr := gokeepasslib.NewEncoder(file).Encode(database)
	closeErr := file.Close()
	if err := errors.Join(encodeErr, closeErr); err != nil {
		t.Fatalf("write KeePass fixture: %v", err)
	}
}
