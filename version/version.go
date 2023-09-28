package version

import (
	"fmt"

	"github.com/docker/verify-docker-cli-plugin/internal/version"
)

func FromBuild() string {
	v := version.FromBuild()
	return fmt.Sprintf("version: %s (%s - %s)\ngit commit: %s", v.Version, v.GoVersion, v.Platform, v.Commit)
}
