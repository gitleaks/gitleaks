package gitlab

import (
	"fmt"
	"net/url"
)

// BuildVariablesService handles communication with the project variables related methods
// of the Gitlab API
//
// Gitlab API Docs : https://docs.gitlab.com/ce/api/build_variables.html
type BuildVariablesService struct {
	client *Client
}

// BuildVariable represents a variable available for each build of the given project
//
// Gitlab API Docs : https://docs.gitlab.com/ce/api/build_variables.html
type BuildVariable struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Protected bool   `json:"protected"`
}

func (v BuildVariable) String() string {
	return Stringify(v)
}

// ListBuildVariablesOptions are the parameters to ListBuildVariables()
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#list-project-variables
type ListBuildVariablesOptions ListOptions

// ListBuildVariables gets the a list of project variables in a project
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#list-project-variables
func (s *BuildVariablesService) ListBuildVariables(pid interface{}, opts *ListBuildVariablesOptions, options ...OptionFunc) ([]*BuildVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, opts, options)
	if err != nil {
		return nil, nil, err
	}

	var v []*BuildVariable
	resp, err := s.client.Do(req, &v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// GetBuildVariable gets a single project variable of a project
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#show-variable-details
func (s *BuildVariablesService) GetBuildVariable(pid interface{}, key string, options ...OptionFunc) (*BuildVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables/%s", url.QueryEscape(project), key)

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	v := new(BuildVariable)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// CreateBuildVariableOptions are the parameters to CreateBuildVariable()
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#create-variable
type CreateBuildVariableOptions struct {
	Key       *string `url:"key" json:"key"`
	Value     *string `url:"value" json:"value"`
	Protected *bool   `url:"protected,omitempty" json:"protected,omitempty"`
}

// CreateBuildVariable creates a variable for a given project
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#create-variable
func (s *BuildVariablesService) CreateBuildVariable(pid interface{}, opt *CreateBuildVariableOptions, options ...OptionFunc) (*BuildVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	v := new(BuildVariable)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// UpdateBuildVariableOptions are the parameters to UpdateBuildVariable()
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#update-variable
type UpdateBuildVariableOptions struct {
	Key       *string `url:"key" json:"key"`
	Value     *string `url:"value" json:"value"`
	Protected *bool   `url:"protected,omitempty" json:"protected,omitempty"`
}

// UpdateBuildVariable updates an existing project variable
// The variable key must exist
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#update-variable
func (s *BuildVariablesService) UpdateBuildVariable(pid interface{}, key string, opt *UpdateBuildVariableOptions, options ...OptionFunc) (*BuildVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables/%s", url.QueryEscape(project), key)

	req, err := s.client.NewRequest("PUT", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	v := new(BuildVariable)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// RemoveBuildVariable removes a project variable of a given project identified by its key
//
// Gitlab API Docs:
// https://docs.gitlab.com/ce/api/build_variables.html#remove-variable
func (s *BuildVariablesService) RemoveBuildVariable(pid interface{}, key string, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/variables/%s", url.QueryEscape(project), key)

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
