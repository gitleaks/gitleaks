package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The child test process exercises the actual CLI without allowing os.Exit
// inside the command to terminate the parent test process.
func TestReportValidationChild(t *testing.T) {
	if os.Getenv("GITLEAKS_REPORT_VALIDATION_CHILD") != "1" {
		return
	}
	os.Args = []string{
		"gitleaks", "dir", os.Getenv("GITLEAKS_TEST_SOURCE"),
		"--no-banner", "--report-path", os.Getenv("GITLEAKS_TEST_REPORT"),
		"--report-format", "handoff-invalid-format",
	}
	Execute()
}

func TestReportValidationPreservesDestination(t *testing.T) {
	for _, exists := range []bool{false, true} {
		name := "absent"
		if exists {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(root, "results.json")
			sentinel := []byte("{\"synthetic_prior_report\":true}\n")
			if exists {
				if err := os.WriteFile(reportPath, sentinel, 0600); err != nil {
					t.Fatal(err)
				}
			}
			child := exec.Command(os.Args[0], "-test.run=^TestReportValidationChild$")
			for _, value := range os.Environ() {
				key := strings.SplitN(value, "=", 2)[0]
				if !strings.HasPrefix(strings.ToUpper(key), "GITLEAKS_") {
					child.Env = append(child.Env, value)
				}
			}
			child.Env = append(child.Env,
				"GITLEAKS_REPORT_VALIDATION_CHILD=1",
				"GITLEAKS_TEST_SOURCE="+source,
				"GITLEAKS_TEST_REPORT="+reportPath,
			)
			output, err := child.CombinedOutput()
			if err == nil {
				t.Fatal("invalid report format unexpectedly succeeded")
			}
			if !strings.Contains(strings.ToLower(string(output)), "unknown report format") {
				t.Fatalf("failed before reaching report-format validation: %s", output)
			}
			data, readErr := os.ReadFile(reportPath)
			if exists {
				if readErr != nil {
					t.Fatalf("prior report no longer readable: %v", readErr)
				}
				if !bytes.Equal(data, sentinel) {
					t.Fatal("prior report changed")
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("validation created a report: %v", readErr)
			}
		})
	}
}
