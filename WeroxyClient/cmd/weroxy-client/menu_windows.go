//go:build windows

package main

import (
	"fmt"
	"os"
)

func runWindowsMenu([]string) int {
	fmt.Fprintln(os.Stderr, "0.3.0 native installation and TUI are Linux only.")
	return 2
}
