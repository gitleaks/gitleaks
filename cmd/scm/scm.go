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
	AzureDevOpsPlatform
	GiteaPlatform
	// TODO: Add others.
)

func (p Platform) String() string {
	return [...]string{
		"unknown",
		"none",
		"github",
		"gitlab",
		"azuredevops",
		"gitea",
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
	case "azuredevops":
		return AzureDevOpsPlatform, nil
	case "gitea":
		return GiteaPlatform, nil
	default:
		return UnknownPlatform, fmt.Errorf("invalid scm platform value: %s", s)
	}
}
