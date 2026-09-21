package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

type loginJob struct {
	name       string
	proxy      string
	username   string
	password   []byte
	totpSource totpSource
	totp       *totpSettings
	tshArgs    []string
}

func (j *loginJob) clear() {
	clear(j.password)
	if j.totp != nil {
		j.totp.clear()
	}
}

func run(ctx context.Context, input *os.File, output, errorOutput io.Writer) error {
	app := application{
		input:               input,
		output:              output,
		errorOutput:         errorOutput,
		readKeePassPassword: getKeePassPassword,
	}
	return app.run(ctx)
}

type application struct {
	input               *os.File
	output              io.Writer
	errorOutput         io.Writer
	readKeePassPassword func(context.Context, keepassPasswordSource, secretInput, io.Writer) ([]byte, error)
}

func (a application) run(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}
	configPath, err := ensureConfig(home, a.errorOutput)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	selected, err := selectTeleport(ctx, a.input, a.errorOutput, cfg.FZFPath, cfg.Teleports)
	if err != nil {
		if errors.Is(err, errSelectionCanceled) {
			return nil
		}
		return err
	}

	tshPath, err := resolveExecutable("tsh", cfg.TSHPath)
	if err != nil {
		return err
	}
	secrets := terminalSecretInput{file: a.input}
	password, err := a.readKeePassPassword(ctx, cfg.KeePassPassword.Source, secrets, a.errorOutput)
	if err != nil {
		return err
	}
	defer clear(password)
	database, err := openKeePass(cfg.KeePassDB, password)
	clear(password)
	if err != nil {
		return err
	}

	selectedTeleports := cfg.Teleports
	if !selected.all {
		selectedTeleports = cfg.Teleports[selected.index : selected.index+1]
	}
	jobs, prepareErr := prepareLoginJobs(database, selectedTeleports)
	lockErr := database.LockProtectedEntries()
	if lockErr != nil {
		for i := range jobs {
			jobs[i].clear()
		}
		return errors.Join(prepareErr, fmt.Errorf("lock protected KeePass entries: %w", lockErr))
	}
	if prepareErr != nil && !selected.all {
		return prepareErr
	}

	runner := loginRunner{
		input:          secrets,
		statusOutput:   a.output,
		terminalOutput: a.errorOutput,
		tshPath:        tshPath,
		timeout:        cfg.loginTimeout(),
	}
	loginErr := runner.loginJobs(ctx, jobs, selected.all)
	return errors.Join(prepareErr, loginErr)
}

func prepareLoginJobs(database *gokeepasslib.Database, teleports []teleport) ([]loginJob, error) {
	jobs := make([]loginJob, 0, len(teleports))
	var errs []error
	for _, tp := range teleports {
		job, err := prepareLoginJob(database, tp)
		if err != nil {
			errs = append(errs, fmt.Errorf("prepare %s (%s): %w", tp.Name, tp.Proxy, err))
			continue
		}
		jobs = append(jobs, job)
	}
	return jobs, errors.Join(errs...)
}

func prepareLoginJob(database *gokeepasslib.Database, tp teleport) (loginJob, error) {
	entry, err := findEntry(database, tp.KeePassEntry)
	if err != nil {
		return loginJob{}, err
	}
	username := entry.GetContent("UserName")
	if username == "" {
		return loginJob{}, errors.New("KeePass entry has no UserName")
	}
	password := []byte(entry.GetPassword())
	if len(password) == 0 {
		return loginJob{}, errors.New("KeePass entry has no Password")
	}

	job := loginJob{
		name:       tp.Name,
		proxy:      tp.Proxy,
		username:   username,
		password:   password,
		totpSource: tp.TOTPSource,
		tshArgs:    append([]string(nil), tp.TSHArgs...),
	}
	if tp.TOTPSource == totpSourceKeePass {
		settings, err := parseTOTPSettings(entry.GetContent("otp"))
		if err != nil {
			job.clear()
			return loginJob{}, err
		}
		job.totp = &settings
	}
	return job, nil
}

type loginRunner struct {
	input          secretInput
	statusOutput   io.Writer
	terminalOutput io.Writer
	tshPath        string
	timeout        time.Duration
	login          func(context.Context, *loginJob) error
}

func (r loginRunner) loginJobs(ctx context.Context, jobs []loginJob, loginAll bool) error {
	defer func() {
		for i := range jobs {
			jobs[i].clear()
		}
	}()

	var errs []error
	for i := range jobs {
		job := &jobs[i]
		login := r.login
		if login == nil {
			login = r.loginOne
		}
		err := login(ctx, job)
		job.clear()
		if err != nil {
			err = fmt.Errorf("login to %s (%s): %w", job.name, job.proxy, err)
			errs = append(errs, err)
			if loginAll {
				if _, writeErr := fmt.Fprintf(r.statusOutput, "==> %s (%s): failed\n", job.name, job.proxy); writeErr != nil {
					errs = append(errs, fmt.Errorf("write login status: %w", writeErr))
					break
				}
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if loginAll {
			if _, err := fmt.Fprintf(r.statusOutput, "==> %s (%s): ok\n", job.name, job.proxy); err != nil {
				errs = append(errs, fmt.Errorf("write login status: %w", err))
				break
			}
		} else {
			if _, err := fmt.Fprintln(r.statusOutput, "Switched context to", job.proxy); err != nil {
				errs = append(errs, fmt.Errorf("write login status: %w", err))
				break
			}
		}
	}
	return errors.Join(errs...)
}

func resolveExecutable(name, configuredPath string) (string, error) {
	path := configuredPath
	if path == "" {
		var err error
		path, err = exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("find %s in PATH: %w", name, err)
		}
	} else if !filepath.IsAbs(path) {
		return "", fmt.Errorf("configured %s path must be absolute", name)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", name, err)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect %s executable %q: %w", name, path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s path %q is not an executable regular file", name, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("refusing insecure %s executable %q: file is group- or world-writable", name, path)
	}
	if err := validateExecutableOwner(name, path, "file", info); err != nil {
		return "", err
	}
	if err := validateExecutableParents(name, path); err != nil {
		return "", err
	}
	return path, nil
}

func validateExecutableParents(name, path string) error {
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Stat(directory)
		if err != nil {
			return fmt.Errorf("inspect parent directory for %s executable %q: %w", name, path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("parent path %q for %s executable is not a directory", directory, name)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf(
				"refusing insecure %s executable %q: parent directory %q is world-writable",
				name,
				path,
				directory,
			)
		}
		if err := validateExecutableOwner(name, path, "parent directory "+directory, info); err != nil {
			return err
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
	}
}

func validateExecutableOwner(name, path, subject string, info os.FileInfo) error {
	ownerUID, err := fileOwnerUID(info)
	if err != nil {
		return fmt.Errorf("inspect owner of %s for %s executable %q: %w", subject, name, path, err)
	}
	currentUID := effectiveUID()
	if !isTrustedExecutableOwner(ownerUID, currentUID) {
		return fmt.Errorf(
			"refusing insecure %s executable %q: %s is owned by UID %d, not root or current UID %d",
			name,
			path,
			subject,
			ownerUID,
			currentUID,
		)
	}
	return nil
}

func isTrustedExecutableOwner(ownerUID uint32, currentUID int) bool {
	return ownerUID == 0 || int64(ownerUID) == int64(currentUID)
}
