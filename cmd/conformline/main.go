package main

import (
	"github.com/vincentsch/conformline/internal/cli"
	"os"
)

func main() { os.Exit(cli.New().Run(os.Args[1:], os.Stdout, os.Stderr)) }
