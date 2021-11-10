package report

import (
	"os"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE             = "CWE-798"
	CWE_DESCRIPTION = "Use of Hard-coded Credentials"
)

func Write(findings []*Finding, cfg config.Config, ext string, reportPath string) error {
	if len(findings) == 0 {
		return nil
	}
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	ext = strings.ToLower(ext)
	switch ext {
	case ".json", "json":
		writeJson(findings, file)
	case ".csv", "csv":
		writeCsv(findings, file)
	case ".sarif", "sarif":
		writeSarif(cfg, findings, file)

	}

	return nil
}
