// Command generate-command-docs maintains the generated command reference.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vincentsch/fendkit/internal/cli"
	"github.com/vincentsch/rungrad/docsgen"
)

func main() {
	check := flag.Bool("check", false, "check reference content without changing files")
	flag.Parse()
	if err := generate(*check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(check bool) error {
	const dir = "docs/reference"
	app := cli.New()
	if !check {
		return docsgen.Write(app, dir)
	}
	result, err := docsgen.Check(app, dir)
	if err != nil {
		return err
	}
	if !result.OK() {
		return fmt.Errorf("command reference differs: missing %v; stale %v; orphaned %v; run make docs", result.Missing, result.Stale, result.Orphaned)
	}
	return nil
}
