// Package version shares build metadata across commands, reports and requests.
package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// Version and Commit may be supplied with -ldflags -X.
var Version string
var Commit string

func init() {
	info, _ := debug.ReadBuildInfo()
	Version, Commit = resolve(Version, Commit, info)
}

// Go 1.27 stamps untagged checkouts with a pseudo-version, even for local builds.
var sourceVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-.*[0-9]{14}-[0-9a-f]+(?:\+dirty)?$`)

func resolve(toolVersion, commit string, info *debug.BuildInfo) (string, string) {
	if info != nil {
		revision := ""
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
				break
			}
		}
		if toolVersion == "" {
			toolVersion = info.Main.Version
			if revision != "" && sourceVersion.MatchString(toolVersion) {
				toolVersion = "dev"
			}
		}
		if commit == "" {
			commit = revision
		}
	}
	if toolVersion == "" || toolVersion == "(devel)" {
		toolVersion = "dev"
	}
	if commit == "" {
		commit = "dev"
	}
	return strings.TrimPrefix(toolVersion, "v"), commit
}
