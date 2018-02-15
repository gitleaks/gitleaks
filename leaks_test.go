package main

import "testing"

func TestGetLocalRepoName(t *testing.T) {
	cases := []struct{
		name string
		input string
		expected string
	}{
		{
			"Usual github url",
			"https://github.com/usual/url",
			"url",
		},
		{
			"Usual github url with .git suffix",
			"https://github.com/usual/url.git",
			"url",
		},
		{
			"personal git url",
			"git@github.com:url.git",
			"url",
		},
		{
			"personal git url in sub folder",
			"git@github.com:sub/url.git",
			"url",
		},
		{
			"ssh git url with port",
			"ssh://git@github.com:2222/sub/url.git",
			"url",
		},
		{
			"local git in sub folder",
			"local/url.git",
			"url",
		},
		{
			"local git in same folder",
			"url.git",
			"url",
		},
	}

	for _, c := range cases {
		actual := getLocalRepoName(c.input)
		if actual != c.expected {
			t.Errorf("'%s' failed. Input: '%s'; Expected: '%s'; Got: '%s'", c.input, c.name, c.expected, actual)
		}
	}
}