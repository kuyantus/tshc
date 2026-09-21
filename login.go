package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/creack/pty"
)

const promptBufferLimit = 16 * 1024

var (
	passwordPrompts = [][]byte{
		[]byte("enter password"),
	}
	codePrompts = [][]byte{
		[]byte("enter your otp"),
		[]byte("enter an otp code"),
		[]byte("enter a code from a otp device"),
		[]byte("enter a code from an otp device"),
	}
)

func (r loginRunner) loginOne(ctx context.Context, job *loginJob) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	args := []string{"login", "--proxy=" + job.proxy, "--user=" + job.username}
	args = append(args, job.tshArgs...)
	command := exec.CommandContext(ctx, r.tshPath, args...) // #nosec G204 -- tshPath is resolved and validated; arguments are passed without a shell.
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	terminal, err := pty.Start(command)
	if err != nil {
		return fmt.Errorf("start tsh: %w", err)
	}
	restoreEcho, err := disableTerminalEcho(int(terminal.Fd()))
	if err != nil {
		cancel()
		_ = terminal.Close()
		_ = command.Wait()
		return fmt.Errorf("disable tsh terminal echo: %w", err)
	}
	closedOnCancel := make(chan struct{})
	closeOnCancel := context.AfterFunc(ctx, func() {
		_ = terminal.Close()
		close(closedOnCancel)
	})

	exchangeErr := exchangePrompts(ctx, terminal, r.terminalOutput, func(kind promptKind) ([]byte, error) {
		switch kind {
		case promptPassword:
			return append([]byte(nil), job.password...), nil
		case promptTOTP:
			return job.readTOTP(ctx, r.input, r.terminalOutput)
		default:
			return nil, fmt.Errorf("unsupported prompt kind %d", kind)
		}
	})
	if exchangeErr != nil {
		cancel()
	}
	if !closeOnCancel() {
		<-closedOnCancel
	}
	restoreErr := restoreEcho()
	closeErr := terminal.Close()
	waitErr := command.Wait()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if exchangeErr != nil {
		return exchangeErr
	}
	if restoreErr != nil && !errors.Is(restoreErr, os.ErrClosed) {
		return fmt.Errorf("restore tsh terminal echo: %w", restoreErr)
	}
	if closeErr != nil && !errors.Is(closeErr, io.EOF) && !errors.Is(closeErr, os.ErrClosed) {
		return fmt.Errorf("close tsh terminal: %w", closeErr)
	}
	if waitErr != nil {
		return fmt.Errorf("tsh exited unsuccessfully: %w", waitErr)
	}
	return nil
}

func (j *loginJob) readTOTP(ctx context.Context, input secretInput, output io.Writer) ([]byte, error) {
	if j.totpSource == totpSourceKeePass {
		if j.totp == nil {
			return nil, errors.New("KeePass TOTP settings are missing")
		}
		code, err := j.totp.generate(time.Now())
		if err != nil {
			return nil, err
		}
		return []byte(code), nil
	}

	if _, err := fmt.Fprintf(output, "TOTP for %s (%s): ", j.name, j.proxy); err != nil {
		return nil, fmt.Errorf("write TOTP prompt: %w", err)
	}
	code, err := input.ReadSecret(ctx)
	if _, newlineErr := fmt.Fprintln(output); newlineErr != nil {
		clear(code)
		return nil, fmt.Errorf("finish TOTP prompt: %w", newlineErr)
	}
	if err != nil {
		clear(code)
		return nil, fmt.Errorf("read TOTP: %w", err)
	}
	if len(code) != 6 && len(code) != 8 {
		clear(code)
		return nil, errors.New("TOTP must contain 6 or 8 digits")
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			clear(code)
			return nil, errors.New("TOTP must contain digits only")
		}
	}
	return code, nil
}

type promptKind uint8

const (
	promptPassword promptKind = iota + 1
	promptTOTP
)

func exchangePrompts(
	ctx context.Context,
	terminal io.ReadWriter,
	output io.Writer,
	secret func(promptKind) ([]byte, error),
) error {
	buffer := make([]byte, 4096)
	pending := make([]byte, 0, 4096)
	passwordSent := false
	totpSent := false

	for {
		count, readErr := terminal.Read(buffer)
		if count > 0 {
			pending = append(pending, buffer[:count]...)

			kind, promptStart, found := detectPromptSuffix(pending)
			if found {
				if err := writeTerminalOutput(output, pending[:promptStart]); err != nil {
					return err
				}
				pending = pending[:0]

				switch kind {
				case promptPassword:
					if passwordSent {
						return errors.New("tsh requested the password more than once; refusing to retry automatically")
					}
					passwordSent = true
				case promptTOTP:
					if !passwordSent {
						return errors.New("tsh requested a TOTP before the password; refusing an unexpected prompt sequence")
					}
					if totpSent {
						return errors.New("tsh requested a TOTP more than once; refusing to retry automatically")
					}
					totpSent = true
				}

				value, err := secret(kind)
				if err != nil {
					return err
				}
				if file, ok := terminal.(interface{ Fd() uintptr }); ok {
					if _, err := disableTerminalEcho(int(file.Fd())); err != nil {
						clear(value)
						return fmt.Errorf("disable tsh terminal echo before answering prompt: %w", err)
					}
				}
				if err := writeSecret(terminal, value); err != nil {
					clear(value)
					return err
				}
				clear(value)
			} else {
				completeLines := bytes.LastIndexByte(pending, '\n') + 1
				if completeLines > 0 {
					if err := writeTerminalOutput(output, pending[:completeLines]); err != nil {
						return err
					}
					pending = append(pending[:0], pending[completeLines:]...)
				}
				if len(pending) > promptBufferLimit {
					overflow := len(pending) - promptBufferLimit
					if err := writeTerminalOutput(output, pending[:overflow]); err != nil {
						return err
					}
					pending = append(pending[:0], pending[overflow:]...)
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, syscall.EIO) {
				if err := writeTerminalOutput(output, pending); err != nil {
					return err
				}
				return nil
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("read tsh terminal: %w", readErr)
		}
	}
}

func detectPrompt(buffer []byte) (promptKind, bool) {
	kind, _, found := detectPromptSuffix(buffer)
	return kind, found
}

func detectPromptSuffix(buffer []byte) (promptKind, int, bool) {
	end := len(buffer)
	for end > 0 && isASCIISpace(buffer[end-1]) {
		end--
	}
	if end == 0 {
		return 0, 0, false
	}

	start := bytes.LastIndexAny(buffer[:end], "\r\n") + 1
	line := bytes.TrimSpace(buffer[start:end])
	if !bytes.HasSuffix(line, []byte(":")) {
		return 0, 0, false
	}
	for _, prompt := range passwordPrompts {
		if hasPrefixFold(line, prompt) {
			return promptPassword, start, true
		}
	}
	for _, prompt := range codePrompts {
		if hasPrefixFold(line, prompt) {
			return promptTOTP, start, true
		}
	}
	return 0, 0, false
}

func hasPrefixFold(value, prefix []byte) bool {
	return len(value) >= len(prefix) && bytes.EqualFold(value[:len(prefix)], prefix)
}

func isASCIISpace(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

func writeTerminalOutput(output io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := output.Write(data)
		if err != nil {
			return fmt.Errorf("write tsh output: %w", err)
		}
		if written == 0 {
			return fmt.Errorf("write tsh output: %w", io.ErrShortWrite)
		}
		data = data[written:]
	}
	return nil
}

func writeSecret(writer io.Writer, secret []byte) error {
	line := make([]byte, len(secret)+1)
	copy(line, secret)
	line[len(secret)] = '\n'
	defer clear(line)

	for len(line) > 0 {
		written, err := writer.Write(line)
		if err != nil {
			return fmt.Errorf("answer tsh prompt: %w", err)
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		line = line[written:]
	}
	return nil
}
