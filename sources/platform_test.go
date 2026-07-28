package sources

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
)

func Test_platformFromHost(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		expected scm.Platform
	}{
		{"github", "https://github.com/owner/repo.git", scm.GitHubPlatform},
		{"github uppercase host", "https://GitHub.com/owner/repo.git", scm.GitHubPlatform},
		{"github with port", "https://github.com:443/owner/repo.git", scm.GitHubPlatform},
		{"gitlab", "https://gitlab.com/owner/repo.git", scm.GitLabPlatform},
		{"azure devops", "https://dev.azure.com/org/project/_git/repo", scm.AzureDevOpsPlatform},
		{"visualstudio", "https://visualstudio.com/org/repo", scm.AzureDevOpsPlatform},
		{"gitea", "https://gitea.com/owner/repo.git", scm.GiteaPlatform},
		{"forgejo", "https://code.forgejo.org/owner/repo.git", scm.GiteaPlatform},
		{"codeberg", "https://codeberg.org/owner/repo.git", scm.GiteaPlatform},
		{"bitbucket", "https://bitbucket.org/owner/repo.git", scm.BitbucketPlatform},

		// self-hosted instances are not recognised by host name
		{"self hosted gitlab", "https://gitlab.example.com/owner/repo.git", scm.UnknownPlatform},
		{"github enterprise", "https://github.example.com/owner/repo.git", scm.UnknownPlatform},
		{"subdomain of github", "https://api.github.com/owner/repo.git", scm.UnknownPlatform},
		{"unknown host", "https://example.com/owner/repo.git", scm.UnknownPlatform},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)

			require.Equal(t, tt.expected, platformFromHost(u))
		})
	}
}
