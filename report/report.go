package report

import (
	"io"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE             = "CWE-798"
	CWE_DESCRIPTION = "Use of Hard-coded Credentials"
)

func Write(findings []Finding, cfg config.Config, ext string, report io.WriteCloser) error {
	var err error
	ext = strings.ToLower(ext)
	switch ext {
	case ".json", "json":
		err = writeJson(findings, report)
	case ".jsonextra", "jsonextra":
		err = writeJsonExtra(findings, report)
	case ".csv", "csv":
		err = writeCsv(findings, report)
	case ".xml", "junit":
		err = writeJunit(findings, report)
	case ".sarif", "sarif":
		err = writeSarif(cfg, findings, report)
	}

	return err
}
