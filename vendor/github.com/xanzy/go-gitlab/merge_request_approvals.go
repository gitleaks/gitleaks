package gitlab

import (
	"fmt"
	"net/url"
	"time"
)

// MergeRequestApprovalsService handles communication with the merge request
// approvals related methods of the GitLab API. This includes reading/updating
// approval settings and approve/unapproving merge requests
//
// GitLab API docs: https://docs.gitlab.com/ee/api/merge_request_approvals.html
type MergeRequestApprovalsService struct {
	client *Client
}

// MergeRequestApprovals represents GitLab merge request approvals.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/merge_request_approvals.html#merge-request-level-mr-approvals
type MergeRequestApprovals struct {
	ID                   int        `json:"id"`
	ProjectID            int        `json:"project_id"`
	Title                string     `json:"title"`
	Description          string     `json:"description"`
	State                string     `json:"state"`
	CreatedAt            *time.Time `json:"created_at"`
	UpdatedAt            *time.Time `json:"updated_at"`
	MergeStatus          string     `json:"merge_status"`
	ApprovalsBeforeMerge int        `json:"approvals_before_merge"`
	ApprovalsRequired    int        `json:"approvals_required"`
	ApprovalsLeft        int        `json:"approvals_left"`
	ApprovedBy           []struct {
		User struct {
			ID        int    `json:"id"`
			Name      string `json:"name"`
			Username  string `json:"username"`
			State     string `json:"state"`
			AvatarURL string `json:"avatar_url"`
			WebURL    string `json:"web_url"`
		} `json:"user"`
	} `json:"approved_by"`
	Approvers []struct {
		User struct {
			ID        int    `json:"id"`
			Name      string `json:"name"`
			Username  string `json:"username"`
			State     string `json:"state"`
			AvatarURL string `json:"avatar_url"`
			WebURL    string `json:"web_url"`
		} `json:"user"`
	} `json:"approvers"`
	ApproverGroups []struct {
		Group struct {
			ID                   int    `json:"id"`
			Name                 string `json:"name"`
			Path                 string `json:"path"`
			Description          string `json:"description"`
			Visibility           string `json:"visibility"`
			AvatarURL            string `json:"avatar_url"`
			WebURL               string `json:"web_url"`
			FullName             string `json:"full_name"`
			FullPath             string `json:"full_path"`
			LFSEnabled           bool   `json:"lfs_enabled"`
			RequestAccessEnabled bool   `json:"request_access_enabled"`
		} `json:"group"`
	} `json:"approver_group"`
}

func (m MergeRequestApprovals) String() string {
	return Stringify(m)
}

// ApproveMergeRequestOptions represents the available ApproveMergeRequest() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/merge_request_approvals.html#approve-merge-request
type ApproveMergeRequestOptions struct {
	Sha *string `url:"sha,omitempty" json:"sha,omitempty"`
}

// ApproveMergeRequest approves a merge request on GitLab. If a non-empty sha
// is provided then it must match the sha at the HEAD of the MR.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/merge_request_approvals.html#approve-merge-request
func (s *MergeRequestApprovalsService) ApproveMergeRequest(pid interface{}, mr int, opt *ApproveMergeRequestOptions, options ...OptionFunc) (*MergeRequestApprovals, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/merge_requests/%d/approve", url.QueryEscape(project), mr)

	req, err := s.client.NewRequest("GET", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	m := new(MergeRequestApprovals)
	resp, err := s.client.Do(req, m)
	if err != nil {
		return nil, resp, err
	}

	return m, resp, err
}

// UnapproveMergeRequest unapproves a previously approved merge request on GitLab.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/merge_request_approvals.html#unapprove-merge-request
func (s *MergeRequestApprovalsService) UnapproveMergeRequest(pid interface{}, mr int, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/merge_requests/%d/unapprove", url.QueryEscape(project), mr)

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
