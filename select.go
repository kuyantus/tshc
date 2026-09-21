package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const loginAllLabel = "[ALL] Login to all clusters"

var errSelectionCanceled = errors.New("selection canceled")

type selection struct {
	all   bool
	index int
}

func selectTeleport(ctx context.Context, fzfPath string, teleports []teleport) (selection, error) {
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
