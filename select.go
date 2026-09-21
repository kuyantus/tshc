package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	loginAllLabel          = "[ALL] Login to all clusters"
	maxSelectionInputBytes = 32
)

var (
	errSelectionCanceled = errors.New("selection canceled")
	errSelectionTooLong  = errors.New("selection input is too long")
)

type selection struct {
	all   bool
	index int
}

func selectTeleport(
	ctx context.Context,
	input *os.File,
	output io.Writer,
	configuredFZFPath string,
	teleports []teleport,
) (selection, error) {
	fzfPath, err := resolveExecutable("fzf", configuredFZFPath)
	if err == nil {
		return selectTeleportWithFZF(ctx, fzfPath, teleports)
	}
	if configuredFZFPath != "" || !errors.Is(err, exec.ErrNotFound) {
		return selection{}, err
	}
	if _, err := fmt.Fprintln(output, "fzf not found; using basic selector."); err != nil {
		return selection{}, fmt.Errorf("write selector notice: %w", err)
	}
	return selectTeleportInTerminal(ctx, input, output, teleports)
}

func selectTeleportWithFZF(ctx context.Context, fzfPath string, teleports []teleport) (selection, error) {
	var choices bytes.Buffer
	fmt.Fprintf(&choices, "0\t%s\n", loginAllLabel)
	for i, tp := range teleports {
		fmt.Fprintf(&choices, "%d\t%s (%s)\n", i+1, tp.Name, tp.Proxy)
	}

	command := exec.CommandContext(ctx, fzfPath, "--delimiter=\t", "--with-nth=2..")
	command.Stdin = &choices
	output, err := command.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return selection{}, ctxErr
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 130 {
			return selection{}, errSelectionCanceled
		}
		if errors.As(err, &exitError) {
			if detail := strings.TrimSpace(string(exitError.Stderr)); detail != "" {
				return selection{}, fmt.Errorf("run fzf: %w: %s", err, detail)
			}
		}
		return selection{}, fmt.Errorf("run fzf: %w", err)
	}
	return parseSelection(string(output), len(teleports))
}

func selectTeleportInTerminal(
	ctx context.Context,
	input *os.File,
	output io.Writer,
	teleports []teleport,
) (selection, error) {
	if input == nil {
		return selection{}, errors.New("terminal input is unavailable")
	}
	if _, err := fmt.Fprintln(output, "Select a Teleport cluster:"); err != nil {
		return selection{}, fmt.Errorf("write selector heading: %w", err)
	}
	if _, err := fmt.Fprintf(output, "  0) %s\n", loginAllLabel); err != nil {
		return selection{}, fmt.Errorf("write selector choice: %w", err)
	}
	for i, tp := range teleports {
		if _, err := fmt.Fprintf(output, "  %d) %s (%s)\n", i+1, tp.Name, tp.Proxy); err != nil {
			return selection{}, fmt.Errorf("write selector choice: %w", err)
		}
	}

	for {
		if _, err := fmt.Fprintf(output, "Enter selection [0-%d]: ", len(teleports)); err != nil {
			return selection{}, fmt.Errorf("write selector prompt: %w", err)
		}
		choice, err := readSelectionLine(ctx, input)
		if errors.Is(err, io.EOF) {
			return selection{}, errSelectionCanceled
		}
		if err != nil && !errors.Is(err, errSelectionTooLong) {
			return selection{}, fmt.Errorf("read selection: %w", err)
		}
		selected, parseErr := parseTerminalSelection(choice, len(teleports))
		if err == nil && parseErr == nil {
			return selected, nil
		}
		if _, err := fmt.Fprintf(output, "Invalid selection: enter a number from 0 to %d.\n", len(teleports)); err != nil {
			return selection{}, fmt.Errorf("write selector validation error: %w", err)
		}
	}
}

func readSelectionLine(ctx context.Context, input *os.File) (string, error) {
	line := make([]byte, 0, 8)
	tooLong := false
	var character [1]byte
	for {
		if err := waitForTerminalInput(ctx, int(input.Fd())); err != nil {
			return "", err
		}
		count, readErr := input.Read(character[:])
		if count > 0 {
			if character[0] == '\n' {
				if tooLong {
					return "", errSelectionTooLong
				}
				return strings.TrimSuffix(string(line), "\r"), nil
			}
			if len(line) < maxSelectionInputBytes {
				line = append(line, character[0])
			} else {
				tooLong = true
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if tooLong {
					return "", errSelectionTooLong
				}
				if len(line) > 0 {
					return strings.TrimSuffix(string(line), "\r"), nil
				}
			}
			return "", readErr
		}
	}
}

func parseTerminalSelection(choice string, count int) (selection, error) {
	index, err := strconv.Atoi(strings.TrimSpace(choice))
	if err != nil {
		return selection{}, fmt.Errorf("parse selection %q: %w", choice, err)
	}
	if index == 0 {
		return selection{all: true}, nil
	}
	if index < 1 || index > count {
		return selection{}, fmt.Errorf("selection index %d is out of range", index)
	}
	return selection{index: index - 1}, nil
}

func parseSelection(choice string, count int) (selection, error) {
	indexText, _, found := strings.Cut(strings.TrimSpace(choice), "\t")
	if !found {
		return selection{}, fmt.Errorf("invalid fzf selection %q", choice)
	}
	index, err := strconv.Atoi(indexText)
	if err != nil {
		return selection{}, fmt.Errorf("invalid fzf selection index %q: %w", indexText, err)
	}
	if index == 0 {
		return selection{all: true}, nil
	}
	if index < 1 || index > count {
		return selection{}, fmt.Errorf("fzf selection index %d is out of range", index)
	}
	return selection{index: index - 1}, nil
}
