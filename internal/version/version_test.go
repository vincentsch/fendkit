package version

import (
	"runtime/debug"
	"testing"
)

func TestBuildMetadata(t *testing.T) {
	tagged := &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "revision"}}}
	for _, tc := range []struct {
		name, override, commit  string
		info                    *debug.BuildInfo
		wantVersion, wantCommit string
	}{
		{"overrides", "v0.1.0", "injected", tagged, "0.1.0", "injected"},
		{"installed module", "", "", tagged, "1.2.3", "revision"},
		{"source", "", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev", "dev"},
		{"untagged checkout", "", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261020210344-4344eefb93b8+dirty"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "revision"}}}, "dev", "revision"},
		{"module pseudo-version", "", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261020210344-4344eefb93b8"}}, "0.0.0-20261020210344-4344eefb93b8", "dev"},
		{"missing", "", "", nil, "dev", "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, c := resolve(tc.override, tc.commit, tc.info)
			if v != tc.wantVersion || c != tc.wantCommit {
				t.Fatalf("got %s %s", v, c)
			}
		})
	}
}
