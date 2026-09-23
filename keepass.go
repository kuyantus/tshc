package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tobischo/gokeepasslib/v3"
)

type totpSettings struct {
	secret    []byte
	period    uint
	digits    otp.Digits
	algorithm otp.Algorithm
	encoder   otp.Encoder
}

func (s *totpSettings) clear() {
	clear(s.secret)
}

func (s totpSettings) generate(at time.Time) (string, error) {
	code, err := totp.GenerateCodeCustom(string(s.secret), at, totp.ValidateOpts{
		Period:    s.period,
		Skew:      0,
		Digits:    s.digits,
		Algorithm: s.algorithm,
		Encoder:   s.encoder,
	})
	if err != nil {
		return "", fmt.Errorf("generate TOTP: %w", err)
	}
	return code, nil
}

func getKeePassPassword(
	ctx context.Context,
	source keepassPasswordSource,
	input secretInput,
	output io.Writer,
) ([]byte, error) {
	reader := keePassPasswordReader{
		platform: runtime.GOOS,
		source:   source,
		keychain: getPasswordFromKeychain,
		input:    input,
		output:   output,
	}
	return reader.read(ctx)
}

type keePassPasswordReader struct {
	platform string
	source   keepassPasswordSource
	keychain func(context.Context) ([]byte, error)
	input    secretInput
	output   io.Writer
}

func (r keePassPasswordReader) read(ctx context.Context) ([]byte, error) {
	if r.platform == "darwin" && r.source != keepassPasswordSourcePrompt {
		password, err := r.keychain(ctx)
		if err == nil && len(password) != 0 {
			return password, nil
		}
		clear(password)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			if _, writeErr := fmt.Fprintf(r.output, "macOS Keychain unavailable: %v\n", err); writeErr != nil {
				return nil, fmt.Errorf("report unavailable macOS Keychain: %w", writeErr)
			}
		}
	}

	if _, err := fmt.Fprint(r.output, "KeePass password: "); err != nil {
		return nil, fmt.Errorf("write KeePass password prompt: %w", err)
	}
	password, err := r.input.ReadSecret(ctx)
	if _, newlineErr := fmt.Fprintln(r.output); newlineErr != nil {
		clear(password)
		return nil, fmt.Errorf("finish KeePass password prompt: %w", newlineErr)
	}
	if err != nil {
		clear(password)
		return nil, fmt.Errorf("read KeePass password: %w", err)
	}
	if len(password) == 0 {
		clear(password)
		return nil, errors.New("KeePass password must not be empty")
	}
	return password, nil
}

func getPasswordFromKeychain(ctx context.Context) ([]byte, error) {
	command := exec.CommandContext(
		ctx,
		keychainCommand,
		"find-generic-password",
		"-s", keychainService,
		"-a", keychainAccount,
		"-w",
	)
	var output boundedKeychainOutput
	command.Stdout = &output
	err := command.Run()
	if output.exceeded {
		clear(output.data)
		return nil, fmt.Errorf("macOS Keychain password exceeds %d bytes", maxSecretLength)
	}
	if err != nil {
		clear(output.data)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("read KeePass password from macOS Keychain: %w", err)
	}
	return parseKeychainPassword(output.data)
}

var errKeychainOutputTooLarge = errors.New("keychain output is too large")

type boundedKeychainOutput struct {
	data     []byte
	exceeded bool
}

func (o *boundedKeychainOutput) Write(p []byte) (int, error) {
	// Leave room for the trailing CRLF printed by the security command.
	const maxOutputLength = maxSecretLength + 2
	if len(p) > maxOutputLength-len(o.data) {
		o.exceeded = true
		return 0, errKeychainOutputTooLarge
	}
	o.data = append(o.data, p...)
	return len(p), nil
}

func parseKeychainPassword(output []byte) ([]byte, error) {
	password := bytes.TrimRight(output, "\r\n")
	if len(password) == 0 {
		clear(output)
		return nil, errors.New("macOS Keychain returned an empty KeePass password")
	}
	if len(password) > maxSecretLength {
		clear(output)
		return nil, fmt.Errorf("macOS Keychain password exceeds %d bytes", maxSecretLength)
	}
	return password, nil
}

func openKeePass(path string, password []byte) (_ *gokeepasslib.Database, returnErr error) {
	database := gokeepasslib.NewDatabase()
	// DBCredentials expects the SHA-256 hash, as produced by
	// NewPasswordCredentials. Hash bytes directly to avoid a master-password string.
	passwordHash := sha256.Sum256(password)
	database.Credentials = &gokeepasslib.DBCredentials{Passphrase: passwordHash[:]}
	defer clearDatabaseCredentials(database)

	file, err := os.Open(path) // #nosec G304 -- KeePass database path is explicitly supplied by the user config.
	if err != nil {
		return nil, fmt.Errorf("open KeePass database %q: %w", path, err)
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()

	if err := gokeepasslib.NewDecoder(file).Decode(database); err != nil {
		return nil, fmt.Errorf("decode KeePass database %q: %w", path, err)
	}
	if err := database.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("unlock protected KeePass entries: %w", err)
	}
	return database, nil
}

func clearDatabaseCredentials(database *gokeepasslib.Database) {
	if database == nil || database.Credentials == nil {
		return
	}
	clear(database.Credentials.Passphrase)
	clear(database.Credentials.Key)
	clear(database.Credentials.Windows)
	database.Credentials = nil
}

func findEntry(database *gokeepasslib.Database, path string) (*gokeepasslib.Entry, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, errors.New("KeePass entry path must not be empty")
	}
	if database == nil || database.Content == nil || database.Content.Root == nil || len(database.Content.Root.Groups) == 0 {
		return nil, errors.New("KeePass database has no root group")
	}

	parts := strings.Split(path, "/")
	if slices.Contains(parts, "") {
		return nil, fmt.Errorf("KeePass entry path %q contains an empty component", path)
	}
	group := &database.Content.Root.Groups[0]
	for _, name := range parts[:len(parts)-1] {
		var next *gokeepasslib.Group
		for i := range group.Groups {
			if group.Groups[i].Name == name {
				if next != nil {
					return nil, fmt.Errorf("ambiguous KeePass group %q while resolving %q", name, path)
				}
				next = &group.Groups[i]
			}
		}
		if next == nil {
			return nil, fmt.Errorf("KeePass group %q not found while resolving %q", name, path)
		}
		group = next
	}

	title := parts[len(parts)-1]
	var entry *gokeepasslib.Entry
	for i := range group.Entries {
		if group.Entries[i].GetTitle() == title {
			if entry != nil {
				return nil, fmt.Errorf("ambiguous KeePass entry %q", path)
			}
			entry = &group.Entries[i]
		}
	}
	if entry != nil {
		return entry, nil
	}
	return nil, fmt.Errorf("KeePass entry %q not found", path)
}

func parseTOTPSettings(raw string) (totpSettings, error) {
	if raw == "" {
		return totpSettings{}, errors.New("TOTP URI not found in KeePass entry field otp")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return totpSettings{}, errors.New("TOTP URI is malformed")
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		return totpSettings{}, errors.New("TOTP URI must use otpauth://totp")
	}
	query := parsed.Query()
	algorithm := strings.ToUpper(query.Get("algorithm"))
	if algorithm == "" {
		algorithm = "SHA1"
	}
	switch algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return totpSettings{}, errors.New("TOTP algorithm must be SHA1, SHA256, or SHA512")
	}
	digits := query.Get("digits")
	if digits == "" {
		digits = "6"
	}
	if digits != "6" && digits != "8" {
		return totpSettings{}, errors.New("TOTP digits must be 6 or 8")
	}

	key, err := otp.NewKeyFromURL(raw)
	if err != nil {
		return totpSettings{}, errors.New("TOTP URI contains invalid parameters")
	}
	if key.Secret() == "" {
		return totpSettings{}, errors.New("TOTP URI has no secret")
	}
	if key.Period() == 0 || key.Period() > 300 || key.Period() > uint64(^uint(0)) {
		return totpSettings{}, errors.New("TOTP period must be between 1 and 300 seconds")
	}
	return totpSettings{
		secret:    []byte(key.Secret()),
		period:    uint(key.Period()),
		digits:    key.Digits(),
		algorithm: key.Algorithm(),
		encoder:   key.Encoder(),
	}, nil
}
