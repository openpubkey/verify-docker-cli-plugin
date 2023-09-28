package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/docker/verify-docker-cli-plugin/internal"
)

// build-time arguments
var (
	version          = "0.0.0-dev"
	commit           = "n/a"
	userAgent        = internal.ProductName
	versionFromBuild Version
)

// Version information from build time args and environment
type Version struct {
	Version   string
	Commit    string
	GoVersion string
	Compiler  string
	Platform  string

	SbomVersion string
}

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				commit = setting.Value
			}
		}
	}

	versionFromBuild = Version{
		Version:   version,
		Commit:    commit,
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),

		SbomVersion: "8",
	}

	RefreshUserAgent("")
}

func RefreshUserAgent(extra string) {
	shortCommit := commit
	if len(commit) > 7 {
		shortCommit = commit[0:7]
	}

	userAgent = fmt.Sprintf("%s/%s go/%s git-commit/%s os/%s arch/%s", internal.BinaryName, version, runtime.Version(), shortCommit, runtime.GOOS, runtime.GOARCH)
	if extra != "" {
		userAgent = fmt.Sprintf("%s (%s)", userAgent, extra)
	}
}

// FromBuild provides all version details
func FromBuild() Version {
	return versionFromBuild
}

func UserAgent() string {
	return userAgent
}

func (v Version) IsDevBuild() bool {
	return strings.Index(v.Version, "-") > 0
}
