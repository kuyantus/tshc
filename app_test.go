package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
)

func TestApplicationRunEndToEnd(t *testing.T) {
	home := trustedTempDir(t)
	configDirectory := filepath.Join(home, configDirName)
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	const (
		masterPassword   = "master-password-fixture"
		teleportPassword = "teleport-password-fixture"
		totpSecret       = "JBSWY3DPEHPK3PXP" // #nosec G101 -- public TOTP test vector, not a credential.
	)
	databasePath := filepath.Join(home, "passwords.kdbx")
	entry := keepassEntry(teleportPassword)
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key: "otp",
		Value: gokeepasslib.V{
			Content: "otpauth://totp/Teleport:alice?secret=" + totpSecret,
		},
	})
	writeTestKeePassDatabase(t, databasePath, masterPassword, entry)

	binDirectory := filepath.Join(home, "bin")
	if err := os.Mkdir(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	fzfPath := filepath.Join(binDirectory, "fzf")
	if err := writeTestExecutable(fzfPath, "#!/bin/sh\nprintf '1\\tproduction (teleport.example.com)\\n'\n"); err != nil {
		t.Fatal(err)
	}
	tshPath := filepath.Join(binDirectory, "tsh")
	tshScript := `#!/bin/sh
stty echo
printf 'Enter password: '
IFS= read -r password
[ "$password" = 'teleport-password-fixture' ] || exit 10
stty echo
printf 'Enter an OTP code from a device: '
IFS= read -r code
case "$code" in
  [0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) exit 11 ;;
esac
printf 'Login successful\n'
`
	if err := writeTestExecutable(tshPath, tshScript); err != nil {
		t.Fatal(err)
	}

	configYAML := fmt.Sprintf(`keepass_db: %q
login_timeout: 10s
tsh_path: %q
fzf_path: %q
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: production
    totp_source: keepass
`, databasePath, tshPath, fzfPath)
	configPath := filepath.Join(configDirectory, configFileName)
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)
	providedPassword := []byte(masterPassword)
	var output bytes.Buffer
	var terminalOutput bytes.Buffer
	app := application{
		output:      &output,
		errorOutput: &terminalOutput,
		readKeePassPassword: func(context.Context, keepassPasswordSource, secretInput, io.Writer) ([]byte, error) {
			return providedPassword, nil
		},
	}
	if err := app.run(context.Background()); err != nil {
		t.Fatalf("run() error = %v; output = %q; terminal output = %q", err, output.String(), terminalOutput.String())
	}
	if got := output.String(); !strings.Contains(got, "Switched context to teleport.example.com") {
		t.Errorf("output = %q, want switched-context status", got)
	}
	if got := terminalOutput.String(); !strings.Contains(got, "Login successful") {
		t.Errorf("terminal output = %q, want successful login", got)
	}
	combinedOutput := output.String() + terminalOutput.String()
	for _, secret := range []string{masterPassword, teleportPassword, totpSecret} {
		if strings.Contains(combinedOutput, secret) {
			t.Errorf("application output exposes secret %q", secret)
		}
	}
	for _, value := range providedPassword {
		if value != 0 {
			t.Fatal("application did not clear the KeePass password")
		}
	}
}

func TestApplicationFirstRunStopsAfterCreatingConfig(t *testing.T) {
	home := trustedTempDir(t)
	t.Setenv("HOME", home)

	var output bytes.Buffer
	app := application{
		output:      io.Discard,
		errorOutput: &output,
		readKeePassPassword: func(context.Context, keepassPasswordSource, secretInput, io.Writer) ([]byte, error) {
			t.Fatal("first run attempted to read the KeePass password")
			return nil, nil
		},
	}
	if err := app.run(context.Background()); err != nil {
		t.Fatalf("first run error = %v", err)
	}
	configPath := filepath.Join(home, configDirName, configFileName)
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("created config: %v", err)
	}
	if got := output.String(); !strings.Contains(got, configPath) || !strings.Contains(got, "edit it") {
		t.Errorf("first-run output = %q, want edit instruction", got)
	}
}

func TestRunTreatsCanceledSelectionAsSuccess(t *testing.T) {
	home := trustedTempDir(t)
	configDirectory := filepath.Join(home, configDirName)
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	binDirectory := filepath.Join(home, "bin")
	if err := os.Mkdir(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	fzfPath := filepath.Join(binDirectory, "fzf")
	if err := writeTestExecutable(fzfPath, "#!/bin/sh\nexit 130\n"); err != nil {
		t.Fatal(err)
	}

	configYAML := fmt.Sprintf(`keepass_db: /does/not/need/to/exist.kdbx
fzf_path: %q
teleports:
  - name: production
    proxy: teleport.example.com
    keepass_entry: production
`, fzfPath)
	if err := os.WriteFile(filepath.Join(configDirectory, configFileName), []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	if err := run(context.Background(), nil, &output, &errorOutput); err != nil {
		t.Fatalf("run() error = %v, want canceled selection to exit successfully", err)
	}
	if output.Len() != 0 || errorOutput.Len() != 0 {
		t.Errorf("run() output = %q / %q, want no output", output.String(), errorOutput.String())
	}
}

func TestPrepareLoginJobTOTPSource(t *testing.T) {
	t.Parallel()

	entry := keepassEntry("password")
	database := &gokeepasslib.Database{Content: &gokeepasslib.DBContent{Root: &gokeepasslib.RootData{
		Groups: []gokeepasslib.Group{{Name: "Root", Entries: []gokeepasslib.Entry{entry}}},
	}}}

	promptJob, err := prepareLoginJob(database, teleport{
		Name:         "production",
		Proxy:        "teleport.example.com",
		KeePassEntry: "production",
		TOTPSource:   totpSourcePrompt,
	})
	if err != nil {
		t.Fatalf("prepareLoginJob(prompt) error = %v", err)
	}
	t.Cleanup(promptJob.clear)
	if promptJob.totp != nil {
		t.Fatal("prompt job unexpectedly contains KeePass TOTP settings")
	}

	_, err = prepareLoginJob(database, teleport{
		Name:         "production",
		Proxy:        "teleport.example.com",
		KeePassEntry: "production",
		TOTPSource:   totpSourceKeePass,
	})
	if err == nil {
		t.Fatal("prepareLoginJob(keepass) succeeded without otp field")
	}
}

func TestResolveExecutableRejectsWritableParent(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(trustedTempDir(t), "writable")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "tsh")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- executable fixture is owner-only.
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil { // #nosec G302 -- intentionally insecure fixture.
		t.Fatal(err)
	}

	_, err := resolveExecutable("tsh", path)
	if err == nil || !strings.Contains(err.Error(), "parent directory") {
		t.Fatalf("resolveExecutable() error = %v, want writable-parent rejection", err)
	}
}

func TestResolveExecutableRejectsGroupWritableAncestor(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(trustedTempDir(t), "homebrew-cellar")
	binDirectory := filepath.Join(directory, "package", "bin")
	if err := os.MkdirAll(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDirectory, "fzf")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- executable fixture is owner-only.
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o775); err != nil { // #nosec G302 -- models a user-owned Homebrew Cellar.
		t.Fatal(err)
	}

	_, err := resolveExecutable("fzf", path)
	if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("resolveExecutable() error = %v, want group-writable ancestor rejection", err)
	}
}

func TestApplicationRejectsReplaceableExecutableBeforeReadingSecrets(t *testing.T) {
	home := trustedTempDir(t)
	configDirectory := filepath.Join(home, configDirName)
	binDirectory := filepath.Join(home, "shared-bin")
	for _, directory := range []string{configDirectory, binDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tshPath := filepath.Join(binDirectory, "tsh")
	if err := writeTestExecutable(tshPath, "#!/bin/sh\nexit 90\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binDirectory, 0o775); err != nil { // #nosec G302 -- intentionally insecure fixture.
		t.Fatal(err)
	}
	fzfPath := filepath.Join(home, "fzf")
	if err := writeTestExecutable(fzfPath, "#!/bin/sh\nprintf '1\\tfixture\\n'\n"); err != nil {
		t.Fatal(err)
	}
	configYAML := fmt.Sprintf(
		"keepass_db: unused.kdbx\ntsh_path: %q\nfzf_path: %q\nteleports:\n"+
			"  - name: fixture\n    proxy: fixture.invalid\n    keepass_entry: production\n",
		tshPath,
		fzfPath,
	)
	if err := os.WriteFile(filepath.Join(configDirectory, configFileName), []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	app := application{
		output:      io.Discard,
		errorOutput: io.Discard,
		readKeePassPassword: func(context.Context, keepassPasswordSource, secretInput, io.Writer) ([]byte, error) {
			t.Fatal("requested secrets while the validated executable could still be replaced by another group member")
			return nil, nil
		},
	}
	if err := app.run(context.Background()); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("run() error = %v, want rejection before requesting secrets", err)
	}
}

func TestPrepareLoginJobRejectsDuplicateKeePassEntries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		passwords []string
	}{
		{name: "original order", passwords: []string{"dummy-secret-for-cluster-a", "dummy-secret-for-cluster-b"}},
		{name: "reversed order", passwords: []string{"dummy-secret-for-cluster-b", "dummy-secret-for-cluster-a"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			entries := []gokeepasslib.Entry{keepassEntry(test.passwords[0]), keepassEntry(test.passwords[1])}
			path := filepath.Join(t.TempDir(), "duplicates.kdbx")
			writeTestKeePassDatabase(t, path, "dummy-master", entries...)
			database, err := openKeePass(path, []byte("dummy-master"))
			if err != nil {
				t.Fatal(err)
			}
			job, err := prepareLoginJob(database, teleport{
				Name:         "cluster-b",
				Proxy:        "cluster-b.invalid",
				KeePassEntry: "production",
				TOTPSource:   totpSourcePrompt,
			})
			defer job.clear()
			if err == nil || !strings.Contains(err.Error(), "ambiguous KeePass entry") {
				t.Fatalf("prepareLoginJob() error = %v, want ambiguity error", err)
			}
			if len(job.password) != 0 || job.totp != nil {
				t.Fatal("prepared credentials from an ambiguous KeePass path")
			}
			for _, password := range test.passwords {
				if strings.Contains(err.Error(), password) {
					t.Fatal("ambiguity error exposes a password")
				}
			}
		})
	}
}

func TestTrustedExecutableOwner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ownerUID   uint32
		currentUID int
		want       bool
	}{
		{name: "root", ownerUID: 0, currentUID: 501, want: true},
		{name: "current user", ownerUID: 501, currentUID: 501, want: true},
		{name: "different user", ownerUID: 502, currentUID: 501, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := isTrustedExecutableOwner(test.ownerUID, test.currentUID); got != test.want {
				t.Errorf("isTrustedExecutableOwner(%d, %d) = %t, want %t", test.ownerUID, test.currentUID, got, test.want)
			}
		})
	}
}

func TestLoginJobsContinuesAfterPerLoginTimeout(t *testing.T) {
	t.Parallel()

	jobs := []loginJob{
		{name: "first", proxy: "first.example.com", password: []byte("one")},
		{name: "second", proxy: "second.example.com", password: []byte("two")},
	}
	var attempts []string
	var status bytes.Buffer
	runner := loginRunner{
		statusOutput: &status,
		login: func(_ context.Context, job *loginJob) error {
			attempts = append(attempts, job.name)
			if job.name == "first" {
				return context.DeadlineExceeded
			}
			return nil
		},
	}
	err := runner.loginJobs(context.Background(), jobs, true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("loginJobs() error = %v, want deadline exceeded", err)
	}
	if got := strings.Join(attempts, ","); got != "first,second" {
		t.Errorf("attempts = %q, want both logins", got)
	}
	if got := status.String(); !strings.Contains(got, "first (first.example.com): failed") ||
		!strings.Contains(got, "second (second.example.com): ok") {
		t.Errorf("status = %q, want unambiguous statuses", got)
	}
	for i := range jobs {
		for _, value := range jobs[i].password {
			if value != 0 {
				t.Errorf("jobs[%d] password was not cleared", i)
				break
			}
		}
	}
}

func trustedTempDir(t *testing.T) string {
	t.Helper()

	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("get user home directory: %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	var createErrors []error
	for _, root := range []string{homeDirectory, workingDirectory} {
		directory, err := os.MkdirTemp(root, ".tshc-test-")
		if err != nil {
			createErrors = append(createErrors, fmt.Errorf("under %q: %w", root, err))
			continue
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(directory); err != nil {
				t.Errorf("remove trusted temporary directory: %v", err)
			}
		})
		return directory
	}
	t.Fatalf("create trusted temporary directory: %v", errors.Join(createErrors...))
	return ""
}
