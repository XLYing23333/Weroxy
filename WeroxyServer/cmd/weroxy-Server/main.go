package main

import (
	"os"

	"golang.org/x/term"

	"weroxy/server/internal/cli"
)

func main() {
	opt := cli.Option{
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		IsTerminal: term.IsTerminal(int(os.Stdin.Fd())),
		TermRead: func() ([]byte, error) {
			return term.ReadPassword(int(os.Stdin.Fd()))
		},
	}
	os.Exit(cli.Run(os.Args[1:], opt))
}
