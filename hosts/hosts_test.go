package hosts

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/zricethezav/gitleaks/v5/config"
	"github.com/zricethezav/gitleaks/v5/manager"
	"github.com/zricethezav/gitleaks/v5/options"
)

var (
	integration = flag.Bool("integration", false, "run github/gitlab integration test")
)

func TestGithub(t *testing.T) {
	flag.Parse()
	if !*integration {
		fmt.Println("skipping github integration tests")
		return
	}
	if os.Getenv("GITHUB_TOKEN") == "" {
		t.Log("skipping github integration tests, need env var GITLAB_TOKEN")
		return
	}

	tests := []struct {
		opts         options.Options
		desiredLeaks int
	}{
		{
			opts: options.Options{
				Host:        "github",
				User:        "gitleakstest",
				AccessToken: os.Getenv("GITHUB_TOKEN"),
			},
			desiredLeaks: 2,
		},
		{
			opts: options.Options{
				Host:        "github",
				PullRequest: "https://github.com/gitleakstest/gronit/pull/1",
				AccessToken: os.Getenv("GITHUB_TOKEN"),
			},
			desiredLeaks: 4,
		},
	}

	for _, test := range tests {
		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		m, err := manager.NewManager(test.opts, cfg)
		if err != nil {
			t.Error(err)
		}
		err = Run(m)
		if err != nil {
			t.Fatal(err)
		}

		if test.desiredLeaks != len(m.GetLeaks()) {
			t.Errorf("got %d leaks, want %d", len(m.GetLeaks()), test.desiredLeaks)
		}
	}
}

func TestGitlab(t *testing.T) {
	flag.Parse()
	if !*integration {
		fmt.Println("skipping gitlab integration tests")
		return
	}
	if os.Getenv("GITLAB_TOKEN") == "" {
		t.Log("skipping github integration tests, need env var GITLAB_TOKEN")
		return
	}

	tests := []struct {
		opts         options.Options
		desiredLeaks int
	}{
		{
			opts: options.Options{
				Host:        "gitlab",
				User:        "gitleakstest",
				AccessToken: os.Getenv("GITLAB_TOKEN"),
			},
			desiredLeaks: 2,
		},
	}

	for _, test := range tests {
		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		m, err := manager.NewManager(test.opts, cfg)
		if err != nil {
			t.Error(err)
		}
		err = Run(m)
		if err != nil {
			t.Fatal(err)
		}

		if test.desiredLeaks != len(m.GetLeaks()) {
			t.Errorf("got %d leaks, want %d", len(m.GetLeaks()), test.desiredLeaks)
		}
	}
}
