// Command certrally is a certificate enrollment client for the Certificate Management Protocol.
package main

import (
	"context"
	"os"

	"github.com/misiektoja/certrally/internal/cli"
)

// main runs the command line and exits with its status.
func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
