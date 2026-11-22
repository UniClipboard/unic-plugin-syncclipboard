package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	syncclipboard "github.com/UniClipboard/unic-plugin-syncclipboard"
	"github.com/uniclipboard/unic/plugin"
)

func run() error {
	switch {
	case len(os.Args) == 1:
		return plugin.Serve(&syncclipboard.Backend{})
	case len(os.Args) == 3 && os.Args[1] == "credential":
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 128))
		if err != nil {
			return err
		}
		password, err := syncclipboard.Password(strings.TrimSpace(string(data)), os.Args[2])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, password)
		return err
	default:
		return fmt.Errorf("usage: unic-plugin-syncclipboard [credential CHANNEL_ID]")
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
