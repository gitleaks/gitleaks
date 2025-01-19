package scm

import (
	"fmt"
	"strings"
)

type Platform int

const (
	NoPlatform Platform = iota
	GitHubPlatform
	GitLabPlatform
	// TODO: Add others.
)

func (p Platform) String() string {
	return [...]string{
		"none",
		"github",
		"gitlab",
	}[p]
}

func PlatformFromString(s string) (Platform, error) {
	switch strings.ToLower(s) {
	case "", "none":
		return NoPlatform, nil
	case "github":
		return GitHubPlatform, nil
	case "gitlab":
		return GitLabPlatform, nil
	default:
		return NoPlatform, fmt.Errorf("invalid scm platform value: %s", s)
	}
}
