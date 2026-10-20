// Command generate refreshes the bundled example from the repository fixture.
package main

import (
	"log"
	"os"
)

func main() {
	if err := os.RemoveAll("data"); err != nil {
		log.Fatal(err)
	}
	if err := os.CopyFS("data", os.DirFS("../../testdata/wp-plugin")); err != nil {
		log.Fatal(err)
	}
}
