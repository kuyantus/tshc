package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxSecretLength = 4096

type secretInput interface {
	ReadSecret(context.Context) ([]byte, error)
}

type terminalSecretInput struct {
	file *os.File
}

func (i terminalSecretInput) ReadSecret(ctx context.Context) (_ []byte, returnErr error) {
	if i.file == nil {
		return nil, errors.New("terminal input is unavailable")
	}
	restore, err := disableTerminalEcho(int(i.file.Fd()))
	if err != nil {
		return nil, fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, restore())
	}()

	secret := make([]byte, 0, 64)
	buffer := make([]byte, 256)
	defer clear(buffer)
	for {
		if err := waitForTerminalInput(ctx, int(i.file.Fd())); err != nil {
			clear(secret)
			return nil, err
		}
		count, readErr := i.file.Read(buffer)
		if count > 0 {
			for _, character := range buffer[:count] {
				if character == '\n' {
					if len(secret) > 0 && secret[len(secret)-1] == '\r' {
						secret = secret[:len(secret)-1]
					}
					return secret, nil
				}
				if len(secret) == maxSecretLength {
					clear(secret)
					return nil, fmt.Errorf("secret exceeds %d bytes", maxSecretLength)
				}
				secret = append(secret, character)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && len(secret) > 0 {
				return secret, nil
			}
			clear(secret)
			return nil, readErr
		}
	}
}
