//
// Copyright 2017, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package gitlab

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/url"
	"os"
	"time"
)

// ProjectsService handles communication with the repositories related methods
// of the GitLab API.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html
type ProjectsService struct {
	client *Client
}

// Project represents a GitLab project.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html
type Project struct {
	ID                                        int               `json:"id"`
	Description                               string            `json:"description"`
	DefaultBranch                             string            `json:"default_branch"`
	Public                                    bool              `json:"public"`
	Visibility                                VisibilityValue   `json:"visibility"`
	SSHURLToRepo                              string            `json:"ssh_url_to_repo"`
	HTTPURLToRepo                             string            `json:"http_url_to_repo"`
	WebURL                                    string            `json:"web_url"`
	TagList                                   []string          `json:"tag_list"`
	Owner                                     *User             `json:"owner"`
	Name                                      string            `json:"name"`
	NameWithNamespace                         string            `json:"name_with_namespace"`
	Path                                      string            `json:"path"`
	PathWithNamespace                         string            `json:"path_with_namespace"`
	IssuesEnabled                             bool              `json:"issues_enabled"`
	OpenIssuesCount                           int               `json:"open_issues_count"`
	MergeRequestsEnabled                      bool              `json:"merge_requests_enabled"`
	ApprovalsBeforeMerge                      int               `json:"approvals_before_merge"`
	JobsEnabled                               bool              `json:"jobs_enabled"`
	WikiEnabled                               bool              `json:"wiki_enabled"`
	SnippetsEnabled                           bool              `json:"snippets_enabled"`
	ContainerRegistryEnabled                  bool              `json:"container_registry_enabled"`
	CreatedAt                                 *time.Time        `json:"created_at,omitempty"`
	LastActivityAt                            *time.Time        `json:"last_activity_at,omitempty"`
	CreatorID                                 int               `json:"creator_id"`
	Namespace                                 *ProjectNamespace `json:"namespace"`
	ImportStatus                              string            `json:"import_status"`
	ImportError                               string            `json:"import_error"`
	Permissions                               *Permissions      `json:"permissions"`
	Archived                                  bool              `json:"archived"`
	AvatarURL                                 string            `json:"avatar_url"`
	SharedRunnersEnabled                      bool              `json:"shared_runners_enabled"`
	ForksCount                                int               `json:"forks_count"`
	StarCount                                 int               `json:"star_count"`
	RunnersToken                              string            `json:"runners_token"`
	PublicJobs                                bool              `json:"public_jobs"`
	OnlyAllowMergeIfPipelineSucceeds          bool              `json:"only_allow_merge_if_pipeline_succeeds"`
	OnlyAllowMergeIfAllDiscussionsAreResolved bool              `json:"only_allow_merge_if_all_discussions_are_resolved"`
	LFSEnabled                                bool              `json:"lfs_enabled"`
	RequestAccessEnabled                      bool              `json:"request_access_enabled"`
	MergeMethod                               string            `json:"merge_method"`
	ForkedFromProject                         *ForkParent       `json:"forked_from_project"`
	SharedWithGroups                          []struct {
		GroupID          int    `json:"group_id"`
		GroupName        string `json:"group_name"`
		GroupAccessLevel int    `json:"group_access_level"`
	} `json:"shared_with_groups"`
	Statistics   *ProjectStatistics `json:"statistics"`
	Links        *Links             `json:"_links,omitempty"`
	CIConfigPath *string            `json:"ci_config_path"`
}

// Repository represents a repository.
type Repository struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	WebURL            string          `json:"web_url"`
	AvatarURL         string          `json:"avatar_url"`
	GitSSHURL         string          `json:"git_ssh_url"`
	GitHTTPURL        string          `json:"git_http_url"`
	Namespace         string          `json:"namespace"`
	Visibility        VisibilityValue `json:"visibility"`
	PathWithNamespace string          `json:"path_with_namespace"`
	DefaultBranch     string          `json:"default_branch"`
	Homepage          string          `json:"homepage"`
	URL               string          `json:"url"`
	SSHURL            string          `json:"ssh_url"`
	HTTPURL           string          `json:"http_url"`
}

// ProjectNamespace represents a project namespace.
type ProjectNamespace struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	FullPath string `json:"full_path"`
}

// StorageStatistics represents a statistics record for a group or project.
type StorageStatistics struct {
	StorageSize      int64 `json:"storage_size"`
	RepositorySize   int64 `json:"repository_size"`
	LfsObjectsSize   int64 `json:"lfs_objects_size"`
	JobArtifactsSize int64 `json:"job_artifacts_size"`
}

// ProjectStatistics represents a statistics record for a project.
type ProjectStatistics struct {
	StorageStatistics
	CommitCount int `json:"commit_count"`
}

// Permissions represents permissions.
type Permissions struct {
	ProjectAccess *ProjectAccess `json:"project_access"`
	GroupAccess   *GroupAccess   `json:"group_access"`
}

// ProjectAccess represents project access.
type ProjectAccess struct {
	AccessLevel       AccessLevelValue       `json:"access_level"`
	NotificationLevel NotificationLevelValue `json:"notification_level"`
}

// GroupAccess represents group access.
type GroupAccess struct {
	AccessLevel       AccessLevelValue       `json:"access_level"`
	NotificationLevel NotificationLevelValue `json:"notification_level"`
}

// ForkParent represents the parent project when this is a fork.
type ForkParent struct {
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	ID                int    `json:"id"`
	Name              string `json:"name"`
	NameWithNamespace string `json:"name_with_namespace"`
	Path              string `json:"path"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
}

// Links represents a project web links for self, issues, merge_requests,
// repo_branches, labels, events, members.
type Links struct {
	Self          string `json:"self"`
	Issues        string `json:"issues"`
	MergeRequests string `json:"merge_requests"`
	RepoBranches  string `json:"repo_branches"`
	Labels        string `json:"labels"`
	Events        string `json:"events"`
	Members       string `json:"members"`
}

func (s Project) String() string {
	return Stringify(s)
}

// ListProjectsOptions represents the available ListProjects() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#list-projects
type ListProjectsOptions struct {
	ListOptions
	Archived                 *bool             `url:"archived,omitempty" json:"archived,omitempty"`
	OrderBy                  *string           `url:"order_by,omitempty" json:"order_by,omitempty"`
	Sort                     *string           `url:"sort,omitempty" json:"sort,omitempty"`
	Search                   *string           `url:"search,omitempty" json:"search,omitempty"`
	Simple                   *bool             `url:"simple,omitempty" json:"simple,omitempty"`
	Owned                    *bool             `url:"owned,omitempty" json:"owned,omitempty"`
	Membership               *bool             `url:"membership,omitempty" json:"membership,omitempty"`
	Starred                  *bool             `url:"starred,omitempty" json:"starred,omitempty"`
	Statistics               *bool             `url:"statistics,omitempty" json:"statistics,omitempty"`
	Visibility               *VisibilityValue  `url:"visibility,omitempty" json:"visibility,omitempty"`
	WithIssuesEnabled        *bool             `url:"with_issues_enabled,omitempty" json:"with_issues_enabled,omitempty"`
	WithMergeRequestsEnabled *bool             `url:"with_merge_requests_enabled,omitempty" json:"with_merge_requests_enabled,omitempty"`
	MinAccessLevel           *AccessLevelValue `url:"min_access_level,omitempty" json:"min_access_level,omitempty"`
}

// ListProjects gets a list of projects accessible by the authenticated user.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#list-projects
func (s *ProjectsService) ListProjects(opt *ListProjectsOptions, options ...OptionFunc) ([]*Project, *Response, error) {
	req, err := s.client.NewRequest("GET", "projects", opt, options)
	if err != nil {
		return nil, nil, err
	}

	var p []*Project
	resp, err := s.client.Do(req, &p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// ListUserProjects gets a list of projects for the given user.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#list-user-projects
func (s *ProjectsService) ListUserProjects(uid interface{}, opt *ListProjectsOptions, options ...OptionFunc) ([]*Project, *Response, error) {
	user, err := parseID(uid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("users/%s/projects", user)

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var p []*Project
	resp, err := s.client.Do(req, &p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// ProjectUser represents a GitLab project user.
type ProjectUser struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Username  string `json:"username"`
	State     string `json:"state"`
	AvatarURL string `json:"avatar_url"`
	WebURL    string `json:"web_url"`
}

// ListProjectUserOptions represents the available ListProjectsUsers() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#get-project-users
type ListProjectUserOptions struct {
	ListOptions
	Search *string `url:"search,omitempty" json:"search,omitempty"`
}

// ListProjectsUsers gets a list of users for the given project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#get-project-users
func (s *ProjectsService) ListProjectsUsers(pid interface{}, opt *ListProjectUserOptions, options ...OptionFunc) ([]*ProjectUser, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/users", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var p []*ProjectUser
	resp, err := s.client.Do(req, &p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// ProjectLanguages is a map of strings because the response is arbitrary
//
// Gitlab API docs: https://docs.gitlab.com/ce/api/projects.html#languages
type ProjectLanguages map[string]float32

// GetProjectLanguages gets a list of languages used by the project
//
// GitLab API docs:  https://docs.gitlab.com/ce/api/projects.html#languages
func (s *ProjectsService) GetProjectLanguages(pid interface{}, options ...OptionFunc) (*ProjectLanguages, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/languages", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(ProjectLanguages)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// GetProject gets a specific project, identified by project ID or
// NAMESPACE/PROJECT_NAME, which is owned by the authenticated user.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#get-single-project
func (s *ProjectsService) GetProject(pid interface{}, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// ProjectEvent represents a GitLab project event.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#get-project-events
type ProjectEvent struct {
	Title          interface{} `json:"title"`
	ProjectID      int         `json:"project_id"`
	ActionName     string      `json:"action_name"`
	TargetID       interface{} `json:"target_id"`
	TargetType     interface{} `json:"target_type"`
	AuthorID       int         `json:"author_id"`
	AuthorUsername string      `json:"author_username"`
	Data           struct {
		Before            string      `json:"before"`
		After             string      `json:"after"`
		Ref               string      `json:"ref"`
		UserID            int         `json:"user_id"`
		UserName          string      `json:"user_name"`
		Repository        *Repository `json:"repository"`
		Commits           []*Commit   `json:"commits"`
		TotalCommitsCount int         `json:"total_commits_count"`
	} `json:"data"`
	TargetTitle interface{} `json:"target_title"`
}

func (s ProjectEvent) String() string {
	return Stringify(s)
}

// GetProjectEventsOptions represents the available GetProjectEvents() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#get-project-events
type GetProjectEventsOptions ListOptions

// GetProjectEvents gets the events for the specified project. Sorted from
// newest to latest.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#get-project-events
func (s *ProjectsService) GetProjectEvents(pid interface{}, opt *GetProjectEventsOptions, options ...OptionFunc) ([]*ProjectEvent, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/events", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var p []*ProjectEvent
	resp, err := s.client.Do(req, &p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// CreateProjectOptions represents the available CreateProjects() options.
//
// GitLab API docs: https://docs.gitlab.com/ee/api/projects.html#create-project
type CreateProjectOptions struct {
	Name                                      *string           `url:"name,omitempty" json:"name,omitempty"`
	Path                                      *string           `url:"path,omitempty" json:"path,omitempty"`
	DefaultBranch                             *string           `url:"default_branch,omitempty" json:"default_branch,omitempty"`
	NamespaceID                               *int              `url:"namespace_id,omitempty" json:"namespace_id,omitempty"`
	Description                               *string           `url:"description,omitempty" json:"description,omitempty"`
	IssuesEnabled                             *bool             `url:"issues_enabled,omitempty" json:"issues_enabled,omitempty"`
	MergeRequestsEnabled                      *bool             `url:"merge_requests_enabled,omitempty" json:"merge_requests_enabled,omitempty"`
	JobsEnabled                               *bool             `url:"jobs_enabled,omitempty" json:"jobs_enabled,omitempty"`
	WikiEnabled                               *bool             `url:"wiki_enabled,omitempty" json:"wiki_enabled,omitempty"`
	SnippetsEnabled                           *bool             `url:"snippets_enabled,omitempty" json:"snippets_enabled,omitempty"`
	ResolveOutdatedDiffDiscussions            *bool             `url:"resolve_outdated_diff_discussions,omitempty" json:"resolve_outdated_diff_discussions,omitempty"`
	ContainerRegistryEnabled                  *bool             `url:"container_registry_enabled,omitempty" json:"container_registry_enabled,omitempty"`
	SharedRunnersEnabled                      *bool             `url:"shared_runners_enabled,omitempty" json:"shared_runners_enabled,omitempty"`
	Visibility                                *VisibilityValue  `url:"visibility,omitempty" json:"visibility,omitempty"`
	ImportURL                                 *string           `url:"import_url,omitempty" json:"import_url,omitempty"`
	PublicJobs                                *bool             `url:"public_jobs,omitempty" json:"public_jobs,omitempty"`
	OnlyAllowMergeIfPipelineSucceeds          *bool             `url:"only_allow_merge_if_pipeline_succeeds,omitempty" json:"only_allow_merge_if_pipeline_succeeds,omitempty"`
	OnlyAllowMergeIfAllDiscussionsAreResolved *bool             `url:"only_allow_merge_if_all_discussions_are_resolved,omitempty" json:"only_allow_merge_if_all_discussions_are_resolved,omitempty"`
	MergeMethod                               *MergeMethodValue `url:"merge_method,omitempty" json:"merge_method,omitempty"`
	LFSEnabled                                *bool             `url:"lfs_enabled,omitempty" json:"lfs_enabled,omitempty"`
	RequestAccessEnabled                      *bool             `url:"request_access_enabled,omitempty" json:"request_access_enabled,omitempty"`
	TagList                                   *[]string         `url:"tag_list,omitempty" json:"tag_list,omitempty"`
	PrintingMergeRequestLinkEnabled           *bool             `url:"printing_merge_request_link_enabled,omitempty" json:"printing_merge_request_link_enabled,omitempty"`
	CIConfigPath                              *string           `url:"ci_config_path,omitempty" json:"ci_config_path,omitempty"`
	ApprovalsBeforeMerge                      *int              `url:"approvals_before_merge" json:"approvals_before_merge"`
}

// CreateProject creates a new project owned by the authenticated user.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#create-project
func (s *ProjectsService) CreateProject(opt *CreateProjectOptions, options ...OptionFunc) (*Project, *Response, error) {
	req, err := s.client.NewRequest("POST", "projects", opt, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// CreateProjectForUserOptions represents the available CreateProjectForUser()
// options.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#create-project-for-user
type CreateProjectForUserOptions CreateProjectOptions

// CreateProjectForUser creates a new project owned by the specified user.
// Available only for admins.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#create-project-for-user
func (s *ProjectsService) CreateProjectForUser(user int, opt *CreateProjectForUserOptions, options ...OptionFunc) (*Project, *Response, error) {
	u := fmt.Sprintf("projects/user/%d", user)

	req, err := s.client.NewRequest("POST", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// EditProjectOptions represents the available EditProject() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#edit-project
type EditProjectOptions CreateProjectOptions

// EditProject updates an existing project.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#edit-project
func (s *ProjectsService) EditProject(pid interface{}, opt *EditProjectOptions, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s", url.QueryEscape(project))

	req, err := s.client.NewRequest("PUT", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// ForkProject forks a project into the user namespace of the authenticated
// user.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#fork-project
func (s *ProjectsService) ForkProject(pid interface{}, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/fork", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// StarProject stars a given the project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#star-a-project
func (s *ProjectsService) StarProject(pid interface{}, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/star", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// UnstarProject unstars a given project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#unstar-a-project
func (s *ProjectsService) UnstarProject(pid interface{}, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/unstar", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// ArchiveProject archives the project if the user is either admin or the
// project owner of this project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#archive-a-project
func (s *ProjectsService) ArchiveProject(pid interface{}, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/archive", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// UnarchiveProject unarchives the project if the user is either admin or
// the project owner of this project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#unarchive-a-project
func (s *ProjectsService) UnarchiveProject(pid interface{}, options ...OptionFunc) (*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/unarchive", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, err
}

// DeleteProject removes a project including all associated resources
// (issues, merge requests etc.)
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#remove-project
func (s *ProjectsService) DeleteProject(pid interface{}, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s", url.QueryEscape(project))

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// ShareWithGroupOptions represents options to share project with groups
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#share-project-with-group
type ShareWithGroupOptions struct {
	GroupID     *int              `url:"group_id" json:"group_id"`
	GroupAccess *AccessLevelValue `url:"group_access" json:"group_access"`
	ExpiresAt   *string           `url:"expires_at" json:"expires_at"`
}

// ShareProjectWithGroup allows to share a project with a group.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#share-project-with-group
func (s *ProjectsService) ShareProjectWithGroup(pid interface{}, opt *ShareWithGroupOptions, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/share", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, opt, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DeleteSharedProjectFromGroup allows to unshare a project from a group.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#delete-a-shared-project-link-within-a-group
func (s *ProjectsService) DeleteSharedProjectFromGroup(pid interface{}, groupID int, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/share/%d", url.QueryEscape(project), groupID)

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// ProjectMember represents a project member.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#list-project-team-members
type ProjectMember struct {
	ID          int              `json:"id"`
	Username    string           `json:"username"`
	Email       string           `json:"email"`
	Name        string           `json:"name"`
	State       string           `json:"state"`
	CreatedAt   *time.Time       `json:"created_at"`
	AccessLevel AccessLevelValue `json:"access_level"`
}

// ProjectHook represents a project hook.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#list-project-hooks
type ProjectHook struct {
	ID                       int        `json:"id"`
	URL                      string     `json:"url"`
	ProjectID                int        `json:"project_id"`
	PushEvents               bool       `json:"push_events"`
	IssuesEvents             bool       `json:"issues_events"`
	ConfidentialIssuesEvents bool       `json:"confidential_issues_events"`
	MergeRequestsEvents      bool       `json:"merge_requests_events"`
	TagPushEvents            bool       `json:"tag_push_events"`
	NoteEvents               bool       `json:"note_events"`
	JobEvents                bool       `json:"job_events"`
	PipelineEvents           bool       `json:"pipeline_events"`
	WikiPageEvents           bool       `json:"wiki_page_events"`
	EnableSSLVerification    bool       `json:"enable_ssl_verification"`
	CreatedAt                *time.Time `json:"created_at"`
}

// ListProjectHooksOptions represents the available ListProjectHooks() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#list-project-hooks
type ListProjectHooksOptions ListOptions

// ListProjectHooks gets a list of project hooks.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#list-project-hooks
func (s *ProjectsService) ListProjectHooks(pid interface{}, opt *ListProjectHooksOptions, options ...OptionFunc) ([]*ProjectHook, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/hooks", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var ph []*ProjectHook
	resp, err := s.client.Do(req, &ph)
	if err != nil {
		return nil, resp, err
	}

	return ph, resp, err
}

// GetProjectHook gets a specific hook for a project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#get-project-hook
func (s *ProjectsService) GetProjectHook(pid interface{}, hook int, options ...OptionFunc) (*ProjectHook, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/hooks/%d", url.QueryEscape(project), hook)

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	ph := new(ProjectHook)
	resp, err := s.client.Do(req, ph)
	if err != nil {
		return nil, resp, err
	}

	return ph, resp, err
}

// AddProjectHookOptions represents the available AddProjectHook() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#add-project-hook
type AddProjectHookOptions struct {
	URL                      *string `url:"url,omitempty" json:"url,omitempty"`
	PushEvents               *bool   `url:"push_events,omitempty" json:"push_events,omitempty"`
	IssuesEvents             *bool   `url:"issues_events,omitempty" json:"issues_events,omitempty"`
	ConfidentialIssuesEvents *bool   `url:"confidential_issues_events,omitempty" json:"confidential_issues_events,omitempty"`
	MergeRequestsEvents      *bool   `url:"merge_requests_events,omitempty" json:"merge_requests_events,omitempty"`
	TagPushEvents            *bool   `url:"tag_push_events,omitempty" json:"tag_push_events,omitempty"`
	NoteEvents               *bool   `url:"note_events,omitempty" json:"note_events,omitempty"`
	JobEvents                *bool   `url:"job_events,omitempty" json:"job_events,omitempty"`
	PipelineEvents           *bool   `url:"pipeline_events,omitempty" json:"pipeline_events,omitempty"`
	WikiPageEvents           *bool   `url:"wiki_page_events,omitempty" json:"wiki_page_events,omitempty"`
	EnableSSLVerification    *bool   `url:"enable_ssl_verification,omitempty" json:"enable_ssl_verification,omitempty"`
	Token                    *string `url:"token,omitempty" json:"token,omitempty"`
}

// AddProjectHook adds a hook to a specified project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#add-project-hook
func (s *ProjectsService) AddProjectHook(pid interface{}, opt *AddProjectHookOptions, options ...OptionFunc) (*ProjectHook, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/hooks", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	ph := new(ProjectHook)
	resp, err := s.client.Do(req, ph)
	if err != nil {
		return nil, resp, err
	}

	return ph, resp, err
}

// EditProjectHookOptions represents the available EditProjectHook() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#edit-project-hook
type EditProjectHookOptions struct {
	URL                      *string `url:"url,omitempty" json:"url,omitempty"`
	PushEvents               *bool   `url:"push_events,omitempty" json:"push_events,omitempty"`
	IssuesEvents             *bool   `url:"issues_events,omitempty" json:"issues_events,omitempty"`
	ConfidentialIssuesEvents *bool   `url:"confidential_issues_events,omitempty" json:"confidential_issues_events,omitempty"`
	MergeRequestsEvents      *bool   `url:"merge_requests_events,omitempty" json:"merge_requests_events,omitempty"`
	TagPushEvents            *bool   `url:"tag_push_events,omitempty" json:"tag_push_events,omitempty"`
	NoteEvents               *bool   `url:"note_events,omitempty" json:"note_events,omitempty"`
	JobEvents                *bool   `url:"job_events,omitempty" json:"job_events,omitempty"`
	PipelineEvents           *bool   `url:"pipeline_events,omitempty" json:"pipeline_events,omitempty"`
	WikiPageEvents           *bool   `url:"wiki_page_events,omitempty" json:"wiki_page_events,omitempty"`
	EnableSSLVerification    *bool   `url:"enable_ssl_verification,omitempty" json:"enable_ssl_verification,omitempty"`
	Token                    *string `url:"token,omitempty" json:"token,omitempty"`
}

// EditProjectHook edits a hook for a specified project.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#edit-project-hook
func (s *ProjectsService) EditProjectHook(pid interface{}, hook int, opt *EditProjectHookOptions, options ...OptionFunc) (*ProjectHook, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/hooks/%d", url.QueryEscape(project), hook)

	req, err := s.client.NewRequest("PUT", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	ph := new(ProjectHook)
	resp, err := s.client.Do(req, ph)
	if err != nil {
		return nil, resp, err
	}

	return ph, resp, err
}

// DeleteProjectHook removes a hook from a project. This is an idempotent
// method and can be called multiple times. Either the hook is available or not.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#delete-project-hook
func (s *ProjectsService) DeleteProjectHook(pid interface{}, hook int, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/hooks/%d", url.QueryEscape(project), hook)

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// ProjectForkRelation represents a project fork relationship.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#admin-fork-relation
type ProjectForkRelation struct {
	ID                  int        `json:"id"`
	ForkedToProjectID   int        `json:"forked_to_project_id"`
	ForkedFromProjectID int        `json:"forked_from_project_id"`
	CreatedAt           *time.Time `json:"created_at"`
	UpdatedAt           *time.Time `json:"updated_at"`
}

// CreateProjectForkRelation creates a forked from/to relation between
// existing projects.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#create-a-forked-fromto-relation-between-existing-projects.
func (s *ProjectsService) CreateProjectForkRelation(pid int, fork int, options ...OptionFunc) (*ProjectForkRelation, *Response, error) {
	u := fmt.Sprintf("projects/%d/fork/%d", pid, fork)

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	pfr := new(ProjectForkRelation)
	resp, err := s.client.Do(req, pfr)
	if err != nil {
		return nil, resp, err
	}

	return pfr, resp, err
}

// DeleteProjectForkRelation deletes an existing forked from relationship.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#delete-an-existing-forked-from-relationship
func (s *ProjectsService) DeleteProjectForkRelation(pid int, options ...OptionFunc) (*Response, error) {
	u := fmt.Sprintf("projects/%d/fork", pid)

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// ProjectFile represents an uploaded project file
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#upload-a-file
type ProjectFile struct {
	Alt      string `json:"alt"`
	URL      string `json:"url"`
	Markdown string `json:"markdown"`
}

// UploadFile upload a file from disk
//
// GitLab API docs: https://docs.gitlab.com/ce/api/projects.html#upload-a-file
func (s *ProjectsService) UploadFile(pid interface{}, file string, options ...OptionFunc) (*ProjectFile, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/uploads", url.QueryEscape(project))

	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	b := &bytes.Buffer{}
	w := multipart.NewWriter(b)

	fw, err := w.CreateFormFile("file", file)
	if err != nil {
		return nil, nil, err
	}

	_, err = io.Copy(fw, f)
	if err != nil {
		return nil, nil, err
	}
	w.Close()

	req, err := s.client.NewRequest("", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	req.Body = ioutil.NopCloser(b)
	req.ContentLength = int64(b.Len())
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Method = "POST"

	uf := &ProjectFile{}
	resp, err := s.client.Do(req, uf)
	if err != nil {
		return nil, resp, err
	}

	return uf, resp, nil
}

// ListProjectForks gets a list of project forks.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/projects.html#list-forks-of-a-project
func (s *ProjectsService) ListProjectForks(pid interface{}, opt *ListProjectsOptions, options ...OptionFunc) ([]*Project, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/forks", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var forks []*Project
	resp, err := s.client.Do(req, &forks)
	if err != nil {
		return nil, resp, err
	}

	return forks, resp, err
}
