package report

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

type TemplateReporter struct {
	template *template.Template
}

var _ Reporter = (*TemplateReporter)(nil)

func NewTemplateReporter(templatePath string) (*TemplateReporter, error) {
	if templatePath == "" {
		return nil, errors.New("template path cannot be empty")
	}

	file, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	templateText := string(file)

	// TODO: Add helper functions like escaping for JSON, XML, etc.
	t := template.New("custom")
	t = t.Funcs(sprig.TxtFuncMap())
	t, err = t.Parse(templateText)
	if err != nil {
		return nil, fmt.Errorf("error parsing file: %w", err)
	}
	return &TemplateReporter{template: t}, nil
}

// writeTemplate renders the findings using the user-provided template.
// https://www.digitalocean.com/community/tutorials/how-to-use-templates-in-go
func (t *TemplateReporter) Write(w io.WriteCloser, findings []Finding) error {
	if err := t.template.Execute(w, findings); err != nil {
		return err
	}
	return nil
}
