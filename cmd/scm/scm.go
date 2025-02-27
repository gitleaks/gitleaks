package scm

import (
	"fmt"
	"strings"
)

type Platform int

const (
	UnknownPlatform Platform = iota
	NoPlatform               // Explicitly disable the feature
	GitHubPlatform
	GitLabPlatform
	// TODO: Add others.
)

func (p Platform) String() string {
	return [...]string{
		"unknown",
		"none",
		"github",
		"gitlab",
	}[p]
}

func PlatformFromString(s string) (Platform, error) {
	switch strings.ToLower(s) {
	case "", "unknown":
		return UnknownPlatform, nil
	case "none":
		return NoPlatform, nil
	case "github":
		return GitHubPlatform, nil
	case "gitlab":
		return GitLabPlatform, nil
	default:
		return UnknownPlatform, fmt.Errorf("invalid scm platform value: %s", s)
	}
}
