//
// Copyright 2018, Patrick Webster
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
	"fmt"
	"net/url"
)

// ProjectVariablesService handles communication with the
// project variables related methods of the GitLab API.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html
type ProjectVariablesService struct {
	client *Client
}

// ProjectVariable represents a GitLab Project Variable.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html
type ProjectVariable struct {
	Key              string `json:"key"`
	Value            string `json:"value"`
	Protected        bool   `json:"protected"`
	EnvironmentScope string `json:"environment_scope"`
}

func (v ProjectVariable) String() string {
	return Stringify(v)
}

// ListVariables gets a list of all variables in a project.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#list-project-variables
func (s *ProjectVariablesService) ListVariables(pid interface{}, options ...OptionFunc) ([]*ProjectVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables", url.QueryEscape(project))

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	var vs []*ProjectVariable
	resp, err := s.client.Do(req, &vs)
	if err != nil {
		return nil, resp, err
	}

	return vs, resp, err
}

// GetVariable gets a variable.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#show-variable-details
func (s *ProjectVariablesService) GetVariable(pid interface{}, key string, options ...OptionFunc) (*ProjectVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables/%s", url.QueryEscape(project), url.QueryEscape(key))

	req, err := s.client.NewRequest("GET", u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	v := new(ProjectVariable)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// CreateVariableOptions represents the available
// CreateVariable() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#create-variable
type CreateVariableOptions struct {
	Key              *string `url:"key,omitempty" json:"key,omitempty"`
	Value            *string `url:"value,omitempty" json:"value,omitempty"`
	Protected        *bool   `url:"protected,omitempty" json:"protected,omitempty"`
	EnvironmentScope *string `url:"environment_scope,omitempty" json:"environment_scope,omitempty"`
}

// CreateVariable creates a new project variable.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#create-variable
func (s *ProjectVariablesService) CreateVariable(pid interface{}, opt *CreateVariableOptions, options ...OptionFunc) (*ProjectVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables", url.QueryEscape(project))

	req, err := s.client.NewRequest("POST", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	v := new(ProjectVariable)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// UpdateVariableOptions represents the available
// UpdateVariable() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#update-variable
type UpdateVariableOptions struct {
	Key              *string `url:"key,omitempty" json:"key,omitempty"`
	Value            *string `url:"value,omitempty" json:"value,omitempty"`
	Protected        *bool   `url:"protected,omitempty" json:"protected,omitempty"`
	EnvironmentScope *string `url:"environment_scope,omitempty" json:"environment_scope,omitempty"`
}

// UpdateVariable updates the position of an existing
// group issue board list.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#update-variable
func (s *ProjectVariablesService) UpdateVariable(pid interface{}, key string, opt *UpdateVariableOptions, options ...OptionFunc) (*ProjectVariable, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/variables/%s",
		url.QueryEscape(project),
		url.QueryEscape(key),
	)

	req, err := s.client.NewRequest("PUT", u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	v := new(ProjectVariable)
	resp, err := s.client.Do(req, v)
	if err != nil {
		return nil, resp, err
	}

	return v, resp, err
}

// RemoveVariable removes a project's variable.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/project_level_variables.html#remove-variable
func (s *ProjectVariablesService) RemoveVariable(pid interface{}, key string, options ...OptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/variables/%s",
		url.QueryEscape(project),
		url.QueryEscape(key),
	)

	req, err := s.client.NewRequest("DELETE", u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
