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
)

type staticSecretInput struct {
	values [][]byte
	err    error
}

func (i *staticSecretInput) ReadSecret(context.Context) ([]byte, error) {
	if i.err != nil {
		return nil, i.err
	}
	if len(i.values) == 0 {
		return nil, io.EOF
	}
	value := append([]byte(nil), i.values[0]...)
	i.values = i.values[1:]
	return value, nil
}

type scriptedTerminal struct {
	reads  [][]byte
	writes bytes.Buffer
}

func (s *scriptedTerminal) Read(buffer []byte) (int, error) {
	if len(s.reads) == 0 {
		return 0, io.EOF
	}
	chunk := s.reads[0]
	s.reads = s.reads[1:]
	return copy(buffer, chunk), nil
}

func (s *scriptedTerminal) Write(buffer []byte) (int, error) {
	return s.writes.Write(buffer)
}

func TestExchangePromptsHandlesSplitAndModernPrompts(t *testing.T) {
	t.Parallel()

	terminal := &scriptedTerminal{reads: [][]byte{
		[]byte("Teleport client notice\r\n"),
		[]byte("Enter pass"),
		[]byte("word for Teleport user alice:\r\n"),
		[]byte("Enter an OTP code "),
		[]byte("from a device:\r\n"),
		[]byte("Login successful\r\n"),
	}}
	var output bytes.Buffer
	err := exchangePrompts(context.Background(), terminal, &output, func(kind promptKind) ([]byte, error) {
		switch kind {
		case promptPassword:
			return []byte("password"), nil
		case promptTOTP:
			return []byte("123456"), nil
		default:
			t.Fatalf("unexpected prompt kind %d", kind)
			return nil, nil
		}
	})
	if err != nil {
		t.Fatalf("exchangePrompts() error = %v", err)
	}
	if got, want := terminal.writes.String(), "password\n123456\n"; got != want {
		t.Errorf("terminal writes = %q, want %q", got, want)
	}
	if got := output.String(); !strings.Contains(got, "Login successful") {
		t.Errorf("output = %q, want tsh output", got)
	}
	for _, hidden := range []string{"Enter password", "alice", "Enter an OTP code"} {
		if strings.Contains(output.String(), hidden) {
			t.Errorf("output = %q, want prompt fragment %q hidden", output.String(), hidden)
		}
	}
	if got := output.String(); !strings.Contains(got, "Teleport client notice") {
		t.Errorf("output = %q, want non-prompt tsh output preserved", got)
	}
}

func TestExchangePromptsFlushesPartialOutputAtEOF(t *testing.T) {
	t.Parallel()

	terminal := &scriptedTerminal{reads: [][]byte{[]byte("Authentication failed")}}
	var output bytes.Buffer
	if err := exchangePrompts(context.Background(), terminal, &output, func(promptKind) ([]byte, error) {
		t.Fatal("secret callback called without a prompt")
		return nil, nil
	}); err != nil {
		t.Fatalf("exchangePrompts() error = %v", err)
	}
	if got, want := output.String(), "Authentication failed"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestExchangePromptsRejectsAutomaticRetry(t *testing.T) {
	t.Parallel()

	terminal := &scriptedTerminal{reads: [][]byte{
		[]byte("Enter password:\n"),
		[]byte("Authentication failed\nEnter password:\n"),
	}}
	err := exchangePrompts(context.Background(), terminal, io.Discard, func(promptKind) ([]byte, error) {
		return []byte("password"), nil
	})
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("exchangePrompts() error = %v, want retry rejection", err)
	}
	if got, want := terminal.writes.String(), "password\n"; got != want {
		t.Errorf("terminal writes = %q, want %q", got, want)
	}
}

func TestDetectPromptRequiresCurrentPromptLine(t *testing.T) {
	t.Parallel()

	for _, message := range [][]byte{
		[]byte("ERROR: do not enter password here:\n"),
		[]byte("documentation says enter an OTP code from a device:\n"),
		[]byte("Enter password appears in an incomplete sentence"),
	} {
		if kind, found := detectPrompt(message); found {
			t.Errorf("detectPrompt(%q) = %d, true; want no prompt", message, kind)
		}
	}
}

func TestLoginJobReadsPromptTOTP(t *testing.T) {
	t.Parallel()

	job := loginJob{name: "production", proxy: "teleport.example.com", totpSource: totpSourcePrompt}
	input := &staticSecretInput{values: [][]byte{[]byte("123456")}}
	var output bytes.Buffer
	code, err := job.readTOTP(context.Background(), input, &output)
	if err != nil {
		t.Fatalf("readTOTP() error = %v", err)
	}
	defer clear(code)
	if got := string(code); got != "123456" {
		t.Errorf("readTOTP() = %q, want 123456", got)
	}
	if got := output.String(); !strings.Contains(got, "production (teleport.example.com)") {
		t.Errorf("prompt = %q, want cluster identity", got)
	}
}

func TestLoginJobRejectsInvalidPromptTOTP(t *testing.T) {
	t.Parallel()

	for _, code := range []string{"12345", "123456789", "123abc"} {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			job := loginJob{name: "test", proxy: "example.com", totpSource: totpSourcePrompt}
			input := &staticSecretInput{values: [][]byte{[]byte(code)}}
			_, err := job.readTOTP(context.Background(), input, io.Discard)
			if err == nil {
				t.Fatalf("readTOTP(%q) succeeded, want error", code)
			}
		})
	}
}

func TestLoginOneWithPTY(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	tshPath := filepath.Join(directory, "tsh")
	script := `#!/bin/sh
stty echo
printf 'Enter password: '
IFS= read -r password
[ "$password" = 'password' ] || exit 10
stty echo
printf 'Enter an OTP code from a device: '
IFS= read -r code
[ "$code" = '123456' ] || exit 11
printf 'Login successful\n'
`
	if err := writeTestExecutable(tshPath, script); err != nil {
		t.Fatal(err)
	}

	job := loginJob{
		name:       "production",
		proxy:      "teleport.example.com",
		username:   "alice",
		password:   []byte("password"),
		totpSource: totpSourcePrompt,
	}
	var output bytes.Buffer
	runner := loginRunner{
		input:          &staticSecretInput{values: [][]byte{[]byte("123456")}},
		terminalOutput: &output,
		tshPath:        tshPath,
		timeout:        10 * time.Second,
	}
	err := runner.loginOne(context.Background(), &job)
	if err != nil {
		t.Fatalf("loginOne() error = %v; output = %q", err, output.String())
	}
	if !strings.Contains(output.String(), "Login successful") {
		t.Errorf("output = %q, want successful login", output.String())
	}
	if !strings.Contains(output.String(), "TOTP for production (teleport.example.com):") {
		t.Errorf("output = %q, want tshc manual TOTP prompt", output.String())
	}
	for _, hidden := range []string{"Enter password", "Enter an OTP code"} {
		if strings.Contains(output.String(), hidden) {
			t.Errorf("output = %q, want raw tsh prompt %q hidden", output.String(), hidden)
		}
	}
	if strings.Contains(output.String(), "password\r\n") || strings.Contains(output.String(), "123456") {
		t.Errorf("output leaks a secret: %q", output.String())
	}
}

func TestLoginOneTimeoutKillsPTYProcessGroup(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	tshPath := filepath.Join(directory, "tsh")
	script := `#!/bin/sh
trap '' HUP TERM
(trap '' HUP TERM; sleep 30) &
printf 'waiting forever\n'
wait
`
	if err := writeTestExecutable(tshPath, script); err != nil {
		t.Fatal(err)
	}

	runner := loginRunner{
		input:          &staticSecretInput{},
		terminalOutput: io.Discard,
		tshPath:        tshPath,
		timeout:        100 * time.Millisecond,
	}
	started := time.Now()
	err := runner.loginOne(context.Background(), &loginJob{proxy: "example.com", username: "alice"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("loginOne() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("loginOne() returned after %v, timeout was not enforced", elapsed)
	}
}

func writeTestExecutable(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o700) // #nosec G302 -- the owner-only test fixture must be executable.
}
