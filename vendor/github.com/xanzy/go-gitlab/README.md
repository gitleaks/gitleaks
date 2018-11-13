# go-gitlab

A GitLab API client enabling Go programs to interact with GitLab in a simple and uniform way

[![Build Status](https://travis-ci.org/xanzy/go-gitlab.svg?branch=master)](https://travis-ci.org/xanzy/go-gitlab)
[![GitHub license](https://img.shields.io/github/license/xanzy/go-gitlab.svg)](https://github.com/xanzy/go-gitlab/blob/master/LICENSE)
[![Sourcegraph](https://sourcegraph.com/github.com/xanzy/go-gitlab/-/badge.svg)](https://sourcegraph.com/github.com/xanzy/go-gitlab?badge)
[![GoDoc](https://godoc.org/github.com/xanzy/go-gitlab?status.svg)](https://godoc.org/github.com/xanzy/go-gitlab)
[![Go Report Card](https://goreportcard.com/badge/github.com/xanzy/go-gitlab)](https://goreportcard.com/report/github.com/xanzy/go-gitlab)
[![GitHub issues](https://img.shields.io/github/issues/xanzy/go-gitlab.svg)](https://github.com/xanzy/go-gitlab/issues)

## NOTE

Release v0.6.0 (released on 25-08-2017) no longer supports the older V3 Gitlab API. If
you need V3 support, please use the `f-api-v3` branch. This release contains some backwards
incompatible changes that were needed to fully support the V4 Gitlab API.

## Coverage

This API client package covers most of the existing Gitlab API calls and is updated regularly
to add new and/or missing endpoints. Currently the following services are supported:

- [x] Award Emojis
- [x] Branches
- [x] Broadcast Messages
- [x] Project-level Variables
- [x] Group-level Variables
- [x] Commits
- [x] Custom Attributes
- [x] Deployments
- [x] Deploy Keys
- [x] Environments
- [ ] Epics
- [ ] Epic Issues
- [x] Events
- [x] Feature flags
- [ ] Geo Nodes
- [x] Gitignores templates
- [x] GitLab CI Config templates
- [x] Groups
- [x] Group Access Requests
- [x] Group Members
- [x] Issues
- [x] Issue Boards
- [x] Group Issue Boards
- [x] Jobs
- [x] Keys
- [x] Labels
- [ ] License
- [x] Merge Requests
- [x] Merge Request Approvals
- [x] Project Milestones
- [x] Group Milestones
- [x] Namespaces
- [x] Notes (comments)
- [ ] Discussions (threaded comments)
- [x] Notification settings
- [x] Open source license templates
- [x] Pages Domains
- [x] Pipelines
- [x] Pipeline Triggers
- [x] Pipeline Schedules
- [x] Projects (including setting Webhooks)
- [x] Project Access Requests
- [x] Project badges
- [ ] Project import/export
- [x] Project Members
- [x] Project Snippets
- [x] Protected Branches
- [x] Repositories
- [x] Repository Files
- [x] Runners
- [x] Search
- [x] Services
- [x] Settings
- [x] Sidekiq metrics
- [x] Session
- [x] System Hooks
- [x] Tags
- [x] Todos
- [x] Users
- [x] Validate CI configuration
- [x] Version
- [x] Wikis

## Usage

```go
import "github.com/xanzy/go-gitlab"
```

Construct a new GitLab client, then use the various services on the client to
access different parts of the GitLab API. For example, to list all
users:

```go
git := gitlab.NewClient(nil, "yourtokengoeshere")
//git.SetBaseURL("https://git.mydomain.com/api/v3")
users, _, err := git.Users.ListUsers()
```

Some API methods have optional parameters that can be passed. For example,
to list all projects for user "svanharmelen":

```go
git := gitlab.NewClient(nil)
opt := &ListProjectsOptions{Search: gitlab.String("svanharmelen")}
projects, _, err := git.Projects.ListProjects(opt)
```

### Examples

The [examples](https://github.com/xanzy/go-gitlab/tree/master/examples) directory
contains a couple for clear examples, of which one is partially listed here as well:

```go
package main

import (
	"log"

	"github.com/xanzy/go-gitlab"
)

func main() {
	git := gitlab.NewClient(nil, "yourtokengoeshere")

	// Create new project
	p := &gitlab.CreateProjectOptions{
		Name:                 gitlab.String("My Project"),
		Description:          gitlab.String("Just a test project to play with"),
		MergeRequestsEnabled: gitlab.Bool(true),
		SnippetsEnabled:      gitlab.Bool(true),
		Visibility:           gitlab.Visibility(gitlab.PublicVisibility),
	}
	project, _, err := git.Projects.CreateProject(p)
	if err != nil {
		log.Fatal(err)
	}

	// Add a new snippet
	s := &gitlab.CreateProjectSnippetOptions{
		Title:           gitlab.String("Dummy Snippet"),
		FileName:        gitlab.String("snippet.go"),
		Code:            gitlab.String("package main...."),
		Visibility:      gitlab.Visibility(gitlab.PublicVisibility),
	}
	_, _, err = git.ProjectSnippets.CreateSnippet(project.ID, s)
	if err != nil {
		log.Fatal(err)
	}
}
```

For complete usage of go-gitlab, see the full [package docs](https://godoc.org/github.com/xanzy/go-gitlab).

## ToDo

- The biggest thing this package still needs is tests :disappointed:

## Issues

- If you have an issue: report it on the [issue tracker](https://github.com/xanzy/go-gitlab/issues)

## Author

Sander van Harmelen (<sander@xanzy.io>)

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>
