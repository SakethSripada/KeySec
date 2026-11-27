// Command keysec lets coding agents use your secrets without seeing them.
package main

import (
	"os"

	"github.com/sakethsripada/keysec/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], version))
}
