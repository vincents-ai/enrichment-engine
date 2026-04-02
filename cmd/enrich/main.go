package main

import (
	"fmt"
	"os"

	"github.com/shift/enrichment-engine/internal/cli"
)

var Version = "dev"

func main() {
	if err := cli.New(cli.WithVersion(Version)).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
