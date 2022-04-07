package main

import (
	"os"
	"text/template"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	templatePath = "rules/rule.tmpl"
)

func main() {
	configRules := []*config.Rule{}
	configRules = append(configRules, rules.Twitter())
	configRules = append(configRules, rules.Facebook())
	config := config.Config{}
	config.Rules = configRules
	// fmt.Println("heroku: ", NewRule([]string{"heroku"}, "[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"))
	// fmt.Println("mailchimp: ", NewRule([]string{"mailchimp"}, hex32+"-us20"))
	// fmt.Println("facebook: ", NewRule([]string{"facebook"}, hex32))
	// fmt.Println("twitter: ", NewRule([]string{"twitter"}, hex+"{35,44}"))
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create("rules.toml")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create rules.toml")
	}
	tmpl.Execute(f, config)

}
