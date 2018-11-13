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
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// IssuesService handles communication with the issue related methods
// of the GitLab API.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html
type IssuesService struct {
	client    *Client
	timeStats *timeStatsService
}

// Issue represents a GitLab issue.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html
type Issue struct {
	ID        int        `json:"id"`
	IID       int        `json:"iid"`
	ProjectID int        `json:"project_id"`
	Milestone *Milestone `json:"milestone"`
	Author    struct {
		ID        int        `json:"id"`
		Username  string     `json:"username"`
		Email     string     `json:"email"`
		Name      string     `json:"name"`
		State     string     `json:"state"`
		CreatedAt *time.Time `json:"created_at"`
	} `json:"author"`
	Description string `json:"description"`
	State       string `json:"state"`
	Assignees   []struct {
		ID        int        `json:"id"`
		Username  string     `json:"username"`
		Email     string     `json:"email"`
		Name      string     `json:"name"`
		State     string     `json:"state"`
		CreatedAt *time.Time `json:"created_at"`
	} `json:"assignees"`
	Assignee struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Username  string `json:"username"`
		State     string `json:"state"`
		AvatarURL string `json:"avatar_url"`
		WebURL    string `json:"web_url"`
	} `json:"assignee"`
	Upvotes          int        `json:"upvotes"`
	Downvotes        int        `json:"downvotes"`
	Labels           []string   `json:"labels"`
	Title            string     `json:"title"`
	UpdatedAt        *time.Time `json:"updated_at"`
	CreatedAt        *time.Time `json:"created_at"`
	ClosedAt         *time.Time `json:"closed_at"`
	Subscribed       bool       `json:"subscribed"`
	UserNotesCount   int        `json:"user_notes_count"`
	DueDate          *ISOTime   `json:"due_date"`
	WebURL           string     `json:"web_url"`
	TimeStats        *TimeStats `json:"time_stats"`
	Confidential     bool       `json:"confidential"`
	Weight           int        `json:"weight"`
	DiscussionLocked bool       `json:"discussion_locked"`
	Links            struct {
		Self       string `json:"self"`
		Notes      string `json:"notes"`
		AwardEmoji string `json:"award_emoji"`
		Project    string `json:"project"`
	} `json:"_links"`
	IssueLinkID int `json:"issue_link_id"`
}

func (i Issue) String() string {
	return Stringify(i)
}

// Labels is a custom type with specific marshaling characteristics.
type Labels []string

// MarshalJSON implements the json.Marshaler interface.
func (l *Labels) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.Join(*l, ","))
}

// ListIssuesOptions represents the available ListIssues() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#list-issues
type ListIssuesOptions struct {
	ListOptions
	State           *string    `url:"state,omitempty" json:"state,omitempty"`
	Labels          Labels     `url:"labels,comma,omitempty" json:"labels,omitempty"`
	Milestone       *string    `url:"milestone,omitempty" json:"milestone,omitempty"`
	Scope           *string    `url:"scope,omitempty" json:"scope,omitempty"`
	AuthorID        *int       `url:"author_id,omitempty" json:"author_id,omitempty"`
	AssigneeID      *int       `url:"assignee_id,omitempty" json:"assignee_id,omitempty"`
	MyReactionEmoji *string    `url:"my_reaction_emoji,omitempty" json:"my_reaction_emoji,omitempty"`
	IIDs            []int      `url:"iids[],omitempty" json:"iids,omitempty"`
	OrderBy         *string    `url:"order_by,omitempty" json:"order_by,omitempty"`
	Sort            *string    `url:"sort,omitempty" json:"sort,omitempty"`
	Search          *string    `url:"search,omitempty" json:"search,omitempty"`
	CreatedAfter    *time.Time `url:"created_after,omitempty" json:"created_after,omitempty"`
	CreatedBefore   *time.Time `url:"created_before,omitempty" json:"created_before,omitempty"`
	UpdatedAfter    *time.Time `url:"updated_after,omitempty" json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time `url:"updated_before,omitempty" json:"updated_before,omitempty"`
}

// ListIssues gets all issues created by authenticated user. This function
// takes pagination parameters page and per_page to restrict the list of issues.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#list-issues
func (s *IssuesService) ListIssues(opt *ListIssuesOptions, options ...OptionFunc) ([]*Issue, *Response, error) {
	req, err := s.client.NewRequest("GET", "issues", opt, options)
	if err != nil {
		return nil, nil, err
	}

	var i []*Issue
	resp, err := s.client.Do(req, &i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// ListGroupIssuesOptions represents the available ListGroupIssues() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#list-group-issues
type ListGroupIssuesOptions struct {
	ListOptions
	State           *string    `url:"state,omitempty" json:"state,omitempty"`
	Labels          Labels     `url:"labels,comma,omitempty" json:"labels,omitempty"`
	IIDs            []int      `url:"iids[],omitempty" json:"iids,omitempty"`
	Milestone       *string    `url:"milestone,omitempty" json:"milestone,omitempty"`
	Scope           *string    `url:"scope,omitempty" json:"scope,omitempty"`
	AuthorID        *int       `url:"author_id,omitempty" json:"author_id,omitempty"`
	AssigneeID      *int       `url:"assignee_id,omitempty" json:"assignee_id,omitempty"`
	MyReactionEmoji *string    `url:"my_reaction_emoji,omitempty" json:"my_reaction_emoji,omitempty"`
	OrderBy         *string    `url:"order_by,omitempty" json:"order_by,omitempty"`
	Sort            *string    `url:"sort,omitempty" json:"sort,omitempty"`
	Search          *string    `url:"search,omitempty" json:"search,omitempty"`
	CreatedAfter    *time.Time `url:"created_after,omitempty" json:"created_after,omitempty"`
	CreatedBefore   *time.Time `url:"created_before,omitempty" json:"created_before,omitempty"`
	UpdatedAfter    *time.Time `url:"updated_after,omitempty" json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time `url:"updated_before,omitempty" json:"updated_before,omitempty"`
}

// ListGroupIssues gets a list of group issues. This function accepts
// pagination parameters page and per_page to return the list of group issues.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#list-group-issues
func (s *IssuesService) ListGroupIssues(pid interface{}, opt *ListGroupIssuesOptions, options ...OptionFunc) ([]*Issue, *Response, error) {
	group, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("groups/%s/issues", url.QueryEscape(group))

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var i []*Issue
	resp, err := s.client.Do(req, &i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// ListProjectIssuesOptions represents the available ListProjectIssues() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#list-project-issues
type ListProjectIssuesOptions struct {
	ListOptions
	IIDs            []int      `url:"iids[],omitempty" json:"iids,omitempty"`
	State           *string    `url:"state,omitempty" json:"state,omitempty"`
	Labels          Labels     `url:"labels,comma,omitempty" json:"labels,omitempty"`
	Milestone       *string    `url:"milestone,omitempty" json:"milestone,omitempty"`
	Scope           *string    `url:"scope,omitempty" json:"scope,omitempty"`
	AuthorID        *int       `url:"author_id,omitempty" json:"author_id,omitempty"`
	AssigneeID      *int       `url:"assignee_id,omitempty" json:"assignee_id,omitempty"`
	MyReactionEmoji *string    `url:"my_reaction_emoji,omitempty" json:"my_reaction_emoji,omitempty"`
	OrderBy         *string    `url:"order_by,omitempty" json:"order_by,omitempty"`
	Sort            *string    `url:"sort,omitempty" json:"sort,omitempty"`
	Search          *string    `url:"search,omitempty" json:"search,omitempty"`
	CreatedAfter    *time.Time `url:"created_after,omitempty" json:"created_after,omitempty"`
	CreatedBefore   *time.Time `url:"created_before,omitempty" json:"created_before,omitempty"`
	UpdatedAfter    *time.Time `url:"updated_after,omitempty" json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time `url:"updated_before,omitempty" json:"updated_before,omitempty"`
}

// ListProjectIssues gets a list of project issues. This function accepts
// pagination parameters page and per_page to return the list of project issues.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#list-project-issues
func (s *IssuesService) ListProjectIssues(pid interface{}, opt *ListProjectIssuesOptions, options ...OptionFunc) ([]*Issue, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/issues", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var i []*Issue
	resp, err := s.client.Do(req, &i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// GetIssue gets a single project issue.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#single-issues
func (s *IssuesService) GetIssue(pid interface{}, issue int, options ...OptionFunc) (*Issue, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/issues/%d", url.QueryEscape(project), issue)

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	i := new(Issue)
	resp, err := s.client.Do(req, i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// CreateIssueOptions represents the available CreateIssue() options.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#new-issues
type CreateIssueOptions struct {
	Title                              *string    `url:"title,omitempty" json:"title,omitempty"`
	Description                        *string    `url:"description,omitempty" json:"description,omitempty"`
	Confidential                       *bool      `url:"confidential,omitempty" json:"confidential,omitempty"`
	AssigneeIDs                        []int      `url:"assignee_ids,omitempty" json:"assignee_ids,omitempty"`
	MilestoneID                        *int       `url:"milestone_id,omitempty" json:"milestone_id,omitempty"`
	Labels                             Labels     `url:"labels,comma,omitempty" json:"labels,omitempty"`
	CreatedAt                          *time.Time `url:"created_at,omitempty" json:"created_at,omitempty"`
	DueDate                            *ISOTime   `url:"due_date,omitempty" json:"due_date,omitempty"`
	MergeRequestToResolveDiscussionsOf *int       `url:"merge_request_to_resolve_discussions_of,omitempty" json:"merge_request_to_resolve_discussions_of,omitempty"`
	DiscussionToResolve                *string    `url:"discussion_to_resolve,omitempty" json:"discussion_to_resolve,omitempty"`
	Weight                             *int       `url:"weight,omitempty" json:"weight,omitempty"`
}

// CreateIssue creates a new project issue.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#new-issues
func (s *IssuesService) CreateIssue(pid interface{}, opt *CreateIssueOptions, options ...OptionFunc) (*Issue, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/issues", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	i := new(Issue)
	resp, err := s.client.Do(req, i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// UpdateIssueOptions represents the available UpdateIssue() options.
//
// GitLab API docs: https://docs.gitlab.com/ee/api/issues.html#edit-issue
type UpdateIssueOptions struct {
	Title            *string    `url:"title,omitempty" json:"title,omitempty"`
	Description      *string    `url:"description,omitempty" json:"description,omitempty"`
	Confidential     *bool      `url:"confidential,omitempty" json:"confidential,omitempty"`
	AssigneeIDs      []int      `url:"assignee_ids,omitempty" json:"assignee_ids,omitempty"`
	MilestoneID      *int       `url:"milestone_id,omitempty" json:"milestone_id,omitempty"`
	Labels           Labels     `url:"labels,comma,omitempty" json:"labels,omitempty"`
	StateEvent       *string    `url:"state_event,omitempty" json:"state_event,omitempty"`
	UpdatedAt        *time.Time `url:"updated_at,omitempty" json:"updated_at,omitempty"`
	DueDate          *ISOTime   `url:"due_date,omitempty" json:"due_date,omitempty"`
	Weight           *int       `url:"weight,omitempty" json:"weight,omitempty"`
	DiscussionLocked *bool      `url:"discussion_locked,omitempty" json:"discussion_locked,omitempty"`
}

// UpdateIssue updates an existing project issue. This function is also used
// to mark an issue as closed.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#edit-issues
func (s *IssuesService) UpdateIssue(pid interface{}, issue int, opt *UpdateIssueOptions, options ...OptionFunc) (*Issue, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/issues/%d", url.QueryEscape(project), issue)

	req, err := s.client.NewRequest("PUT", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	i := new(Issue)
	resp, err := s.client.Do(req, i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// DeleteIssue deletes a single project issue.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/issues.html#delete-an-issue
func (s *IssuesService) DeleteIssue(pid interface{}, issue int, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/issues/%d", url.QueryEscape(project), issue)

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// SubscribeToIssue subscribes the authenticated user to the given issue to
// receive notifications. If the user is already subscribed to the issue, the
// status code 304 is returned.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/merge_requests.html#subscribe-to-a-merge-request
func (s *IssuesService) SubscribeToIssue(pid interface{}, issue int, options ...OptionFunc) (*Issue, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/issues/%d/subscribe", url.QueryEscape(project), issue)

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	i := new(Issue)
	resp, err := s.client.Do(req, i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// UnsubscribeFromIssue unsubscribes the authenticated user from the given
// issue to not receive notifications from that merge request. If the user
// is not subscribed to the issue, status code 304 is returned.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/merge_requests.html#unsubscribe-from-a-merge-request
func (s *IssuesService) UnsubscribeFromIssue(pid interface{}, issue int, options ...OptionFunc) (*Issue, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/issues/%d/unsubscribe", url.QueryEscape(project), issue)

	req, err := s.client.NewRequest("POST", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	i := new(Issue)
	resp, err := s.client.Do(req, i)
	if err != nil {
		return nil, resp, err
	}

	return i, resp, err
}

// ListMergeRequestsClosingIssueOptions represents the available
// ListMergeRequestsClosingIssue() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#list-merge-requests-that-will-close-issue-on-merge
type ListMergeRequestsClosingIssueOptions ListOptions

// ListMergeRequestsClosingIssue gets all the merge requests that will close
// issue when merged.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#list-merge-requests-that-will-close-issue-on-merge
func (s *IssuesService) ListMergeRequestsClosingIssue(pid interface{}, issue int, opt *ListMergeRequestsClosingIssueOptions, options ...OptionFunc) ([]*MergeRequest, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("/projects/%s/issues/%d/closed_by", url.QueryEscape(project), issue)

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	var m []*MergeRequest
	resp, err := s.client.Do(req, &m)
	if err != nil {
		return nil, resp, err
	}

	return m, resp, err
}

// SetTimeEstimate sets the time estimate for a single project issue.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#set-a-time-estimate-for-an-issue
func (s *IssuesService) SetTimeEstimate(pid interface{}, issue int, opt *SetTimeEstimateOptions, options ...OptionFunc) (*TimeStats, *Response, error) {
	return s.timeStats.setTimeEstimate(pid, "issues", issue, opt, options...)
}

// ResetTimeEstimate resets the time estimate for a single project issue.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#reset-the-time-estimate-for-an-issue
func (s *IssuesService) ResetTimeEstimate(pid interface{}, issue int, options ...OptionFunc) (*TimeStats, *Response, error) {
	return s.timeStats.resetTimeEstimate(pid, "issues", issue, options...)
}

// AddSpentTime adds spent time for a single project issue.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#add-spent-time-for-an-issue
func (s *IssuesService) AddSpentTime(pid interface{}, issue int, opt *AddSpentTimeOptions, options ...OptionFunc) (*TimeStats, *Response, error) {
	return s.timeStats.addSpentTime(pid, "issues", issue, opt, options...)
}

// ResetSpentTime resets the spent time for a single project issue.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#reset-spent-time-for-an-issue
func (s *IssuesService) ResetSpentTime(pid interface{}, issue int, options ...OptionFunc) (*TimeStats, *Response, error) {
	return s.timeStats.resetSpentTime(pid, "issues", issue, options...)
}

// GetTimeSpent gets the spent time for a single project issue.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/issues.html#get-time-tracking-stats
func (s *IssuesService) GetTimeSpent(pid interface{}, issue int, options ...OptionFunc) (*TimeStats, *Response, error) {
	return s.timeStats.getTimeSpent(pid, "issues", issue, options...)
}
