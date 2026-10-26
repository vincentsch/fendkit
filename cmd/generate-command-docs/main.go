// Command generate-command-docs maintains the generated command reference.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
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

func reference() map[string]string {
	app := cli.New()
	pages := docsgen.Generate(app)
	// Omit generic output and preview explanations; flags and long help cover them.
	boilerplate := strings.NewReplacer(
		"\n\nOutput:\n  Shows text you can read in your terminal.\n  Use --json to get JSON for scripts and other programs.", "",
		"## Output\n\nShows text you can read in your terminal.\n\nUse --json to get JSON for scripts and other programs.\n\n", "",
		"## Preview changes\n\nThis command makes changes. Use `--dry-run` to see what would change without changing anything.\n\n", "",
	)
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		path := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
		if page, ok := pages[path]; ok {
			if cmd.Long != "" && cmd.Long != cmd.Short {
				page = strings.Replace(page, "## Usage\n", cmd.Long+"\n\n## Usage\n", 1)
			}
			// Cobra's flag renderer includes value syntax, shorthand and nonzero defaults.
			// Use fresh command trees so inherited flags and build identity stay isolated.
			flags := ""
			if usage := cmd.LocalFlags().FlagUsagesWrapped(0); usage != "" {
				flags += "## Flags\n\n```text\n" + usage + "```\n\n"
			}
			if usage := cmd.InheritedFlags().FlagUsagesWrapped(0); usage != "" {
				flags += "## Inherited flags\n\n```text\n" + usage + "```\n\n"
			}
			if start := strings.Index(page, "## Flags\n"); start >= 0 {
				end := strings.Index(page[start+3:], "\n## ")
				if end < 0 {
					page = page[:start]
				} else {
					page = page[:start] + page[start+3+end+1:]
				}
			}
			page = strings.Replace(page, "## Usage\n", flags+"## Usage\n", 1)
			pages[path] = strings.TrimRight(boilerplate.Replace(page+"\n"), "\n") + "\n"
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(app.Root())
	// The index's global flag list uses the same signatures as each command page.
	index := pages["index.md"]
	if start := strings.Index(index, "## Global flags\n"); start >= 0 {
		pages["index.md"] = index[:start] + "## Global flags\n\n```text\n" + app.Root().PersistentFlags().FlagUsagesWrapped(0) + "```\n"
	}
	return pages
}

func generate(check bool) error {
	const dir = "docs/reference"
	pages := reference()
	paths := make([]string, 0, len(pages))
	for path := range pages {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	drift := []string{}
	if !check {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	for _, path := range paths {
		full := filepath.Join(dir, path)
		if check {
			got, err := os.ReadFile(full)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if string(got) != pages[path] {
				drift = append(drift, path)
			}
		} else if err := os.WriteFile(full, []byte(pages[path]), 0644); err != nil {
			return err
		}
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if _, ok := pages[filepath.ToSlash(rel)]; !ok {
			if check {
				drift = append(drift, rel)
			} else {
				return os.Remove(path)
			}
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(drift) > 0 {
		slices.Sort(drift)
		return fmt.Errorf("command reference differs: %v; run make docs", drift)
	}
	return nil
}
