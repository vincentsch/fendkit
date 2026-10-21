package main

import (
	"github.com/vincentsch/fendkit/internal/cli"
	"os"
)

func main() { os.Exit(cli.New().Run(os.Args[1:], os.Stdout, os.Stderr)) }
