package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	configDirName       = ".tshc"
	configFileName      = "teleports.yaml"
	defaultLoginTimeout = 5 * time.Minute
)

type config struct {
	KeePassDB       string                `yaml:"keepass_db"`
	KeePassPassword keepassPasswordConfig `yaml:"keepass_password,omitempty"`
	LoginTimeout    *configDuration       `yaml:"login_timeout,omitempty"`
	TSHPath         string                `yaml:"tsh_path,omitempty"`
	FZFPath         string                `yaml:"fzf_path,omitempty"`
	Teleports       []teleport            `yaml:"teleports"`
}

type keepassPasswordConfig struct {
	Source keepassPasswordSource `yaml:"source,omitempty"`
}

type keepassPasswordSource string

const (
	keepassPasswordSourceKeychain keepassPasswordSource = "keychain"
	keepassPasswordSourcePrompt   keepassPasswordSource = "prompt"
	legacyKeychainPasswordSource  keepassPasswordSource = "legacy_keychain"
)

type teleport struct {
	Name         string     `yaml:"name"`
	Proxy        string     `yaml:"proxy"`
	KeePassEntry string     `yaml:"keepass_entry,omitempty"`
	TOTPSource   totpSource `yaml:"totp_source,omitempty"`
	TSHArgs      []string   `yaml:"tsh_args,omitempty"`
}

type totpSource string

const (
	totpSourceKeePass totpSource = "keepass"
	totpSourcePrompt  totpSource = "prompt"
)

type configDuration time.Duration

func (d *configDuration) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value, err)
	}
	*d = configDuration(duration)
	return nil
}

func (c config) loginTimeout() time.Duration {
	if c.LoginTimeout == nil {
		return defaultLoginTimeout
	}
	return time.Duration(*c.LoginTimeout)
}

func (c *config) validate() error {
	c.KeePassDB = strings.TrimSpace(c.KeePassDB)
	c.KeePassPassword.Source = keepassPasswordSource(strings.TrimSpace(string(c.KeePassPassword.Source)))
	c.TSHPath = strings.TrimSpace(c.TSHPath)
	c.FZFPath = strings.TrimSpace(c.FZFPath)
	if c.KeePassDB == "" {
		return errors.New("keepass_db must not be empty")
	}
	if c.KeePassPassword.Source == "" {
		c.KeePassPassword.Source = keepassPasswordSourceKeychain
	}
	// Configurations from earlier releases used legacy_keychain for the regular
	// login Keychain. Keep them working while exposing only the simpler
	// keychain/prompt model to new configurations.
	if c.KeePassPassword.Source == legacyKeychainPasswordSource {
		c.KeePassPassword.Source = keepassPasswordSourceKeychain
	}
	switch c.KeePassPassword.Source {
	case keepassPasswordSourceKeychain, keepassPasswordSourcePrompt:
	default:
		return fmt.Errorf(
			"keepass_password.source must be %q or %q",
			keepassPasswordSourceKeychain,
			keepassPasswordSourcePrompt,
		)
	}
	if c.loginTimeout() <= 0 {
		return errors.New("login_timeout must be greater than zero")
	}
	for name, path := range map[string]string{"tsh_path": c.TSHPath, "fzf_path": c.FZFPath} {
		if path != "" && !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
		if strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("%s contains a forbidden control character", name)
		}
	}
	if len(c.Teleports) == 0 {
		return errors.New("teleports must contain at least one entry")
	}

	for i := range c.Teleports {
		tp := &c.Teleports[i]
		tp.Name = strings.TrimSpace(tp.Name)
		tp.Proxy = strings.TrimSpace(tp.Proxy)
		tp.KeePassEntry = strings.TrimSpace(tp.KeePassEntry)
		tp.TOTPSource = totpSource(strings.TrimSpace(string(tp.TOTPSource)))
		if tp.Name == "" {
			return fmt.Errorf("teleports[%d].name must not be empty", i)
		}
		if tp.Proxy == "" {
			return fmt.Errorf("teleports[%d].proxy must not be empty", i)
		}
		if strings.ContainsAny(tp.Name, "\r\n\t") || strings.ContainsAny(tp.Proxy, "\r\n\t") {
			return fmt.Errorf("teleports[%d] name and proxy must not contain control characters", i)
		}
		if tp.TOTPSource == "" {
			tp.TOTPSource = totpSourceKeePass
		}
		switch tp.TOTPSource {
		case totpSourceKeePass:
			if tp.KeePassEntry == "" {
				return fmt.Errorf("teleports[%d].keepass_entry is required for totp_source %q", i, tp.TOTPSource)
			}
		case totpSourcePrompt:
			if tp.KeePassEntry == "" {
				return fmt.Errorf("teleports[%d].keepass_entry is required for the Teleport username and password", i)
			}
		default:
			return fmt.Errorf("teleports[%d].totp_source must be %q or %q", i, totpSourceKeePass, totpSourcePrompt)
		}
		for j, arg := range tp.TSHArgs {
			if strings.ContainsAny(arg, "\x00\r\n") {
				return fmt.Errorf("teleports[%d].tsh_args[%d] contains a forbidden control character", i, j)
			}
		}
	}

	return nil
}

func loadConfig(path string) (_ config, returnErr error) {
	file, err := openRegularNoFollow(path)
	if err != nil {
		return config{}, fmt.Errorf("open regular config %q without following symlinks: %w", path, err)
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	if err := file.Chmod(0o600); err != nil {
		return config{}, fmt.Errorf("set private permissions on config %q: %w", path, err)
	}

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return config{}, fmt.Errorf("decode config %q: multiple YAML documents are not allowed", path)
		}
		return config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return config{}, fmt.Errorf("validate config %q: %w", path, err)
	}
	return cfg, nil
}

func ensureConfig(home string, output io.Writer) (string, bool, error) {
	configDir := filepath.Join(home, configDirName)
	if err := ensurePrivateDir(configDir); err != nil {
		return "", false, err
	}

	configPath := filepath.Join(configDir, configFileName)
	_, err := os.Lstat(configPath)
	switch {
	case err == nil:
		file, openErr := openRegularNoFollow(configPath)
		if openErr != nil {
			return "", false, fmt.Errorf("open regular config %q without following symlinks: %w", configPath, openErr)
		}
		chmodErr := file.Chmod(0o600)
		closeErr := file.Close()
		if err := errors.Join(chmodErr, closeErr); err != nil {
			return "", false, fmt.Errorf("secure config %q: %w", configPath, err)
		}
		return configPath, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", false, fmt.Errorf("inspect config %q: %w", configPath, err)
	}

	if err := writeFileExclusive(configPath, defaultConfig); err != nil {
		return "", false, fmt.Errorf("install initial config: %w", err)
	}
	if _, err := fmt.Fprintln(output, "Created", configPath, "— edit it and run tshc again."); err != nil {
		return "", false, fmt.Errorf("report created config: %w", err)
	}
	return configPath, true, nil
}

func ensurePrivateDir(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create config directory %q: %w", path, err)
	}
	directory, err := openDirectoryNoFollow(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("create config directory %q: %w", path, err)
		}
		return fmt.Errorf("open config directory %q without following symlinks: %w", path, err)
	}
	chmodErr := directory.Chmod(0o700) // #nosec G302 -- directories need execute permission; 0700 is private.
	closeErr := directory.Close()
	if err := errors.Join(chmodErr, closeErr); err != nil {
		return fmt.Errorf("secure config directory %q: %w", path, err)
	}
	return nil
}

func writeFileExclusive(destination string, data []byte) (returnErr error) {
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- destination is inside the validated private config directory.
	if err != nil {
		return fmt.Errorf("create config %q: %w", destination, err)
	}
	created := true
	closed := false
	defer func() {
		if !closed {
			closeErr := destinationFile.Close()
			returnErr = errors.Join(returnErr, closeErr)
		}
		if created && returnErr != nil {
			if removeErr := os.Remove(destination); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, removeErr)
			}
		}
	}()

	if _, err := destinationFile.Write(data); err != nil {
		return fmt.Errorf("write config %q: %w", destination, err)
	}
	if err := destinationFile.Close(); err != nil {
		closed = true
		return fmt.Errorf("close config %q: %w", destination, err)
	}
	closed = true
	created = false
	return nil
}
