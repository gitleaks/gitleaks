package report

import (
	"os"
	"strings"

)

func Write(findings []Finding, ext string, reportPath string) error {
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	ext = strings.ToLower(ext)
	switch ext {
	case ".json", "json":
		writeJson(findings, file)
	case ".csv", "csv":

	case ".sarif", "sarif":

	}

	return nil
}
