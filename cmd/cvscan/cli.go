package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// CLIConfig holds all flag-based configuration.
type CLIConfig struct {
	ID        string // eng_xxx
	Token     string // tok_xxx
	ReposPath string
	Output    string
	Scanners  string // comma-separated: "secrets,iac"
}

func runCLI(ctx context.Context, cfg CLIConfig) error {
	scanners, err := parseScanners(cfg.Scanners)
	if err != nil {
		return err
	}

	// Run scans
	result, err := Orchestrate(ctx, ScanRequest{
		ReposPath: cfg.ReposPath,
		Scanners:  scanners,
	}, func(scanner, repo string, findings int) {
		if findings < 0 {
			fmt.Fprintf(os.Stderr, "  %s / %s ... error\n", scanner, repo)
		} else {
			fmt.Printf("  %s / %s ... %d findings\n", scanner, repo, findings)
		}
	})
	if err != nil {
		return err
	}

	// Summary
	fmt.Printf("\nTotal: %d findings (%d secrets, %d IaC) across %d repos\n",
		result.Summary.TotalFindings,
		result.Summary.SecretsFindings,
		result.Summary.IaCFindings,
		result.Summary.ReposScanned,
	)

	// Write JSON sidecar
	jsonPath := jsonSidecarPath(cfg.Output)
	if err := writeResultsJSON(result, jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write results JSON: %v\n", err)
	} else {
		fmt.Printf("Results saved: %s\n", jsonPath)
	}

	// Generate HTML report
	output := cfg.Output
	if output == "" {
		output = "cvscan-report.html"
	}
	if err := generateHTMLReport(result, output); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}
	fmt.Printf("Report saved: %s\n", output)
	_ = openInBrowser(output)

	// Submit only if --id was provided
	if cfg.ID != "" {
		if err := ValidateID(cfg.ID); err != nil {
			return err
		}
		if cfg.Token == "" {
			return fmt.Errorf("--token is required when --id is provided")
		}
		fmt.Print("\nSubmitting findings to Cloudvisor... ")
		if err := submitFindings(apiBaseURL, cfg.ID, cfg.Token, result); err != nil {
			fmt.Println("FAILED")
			return err
		}
		fmt.Println("Done")
	}

	return nil
}

func parseScanners(input string) ([]Scanner, error) {
	if input == "" {
		return []Scanner{&SecretsScanner{}, &IaCScanner{}}, nil
	}

	var scanners []Scanner
	for _, name := range strings.Split(input, ",") {
		switch strings.TrimSpace(strings.ToLower(name)) {
		case "secrets":
			scanners = append(scanners, &SecretsScanner{})
		case "iac":
			scanners = append(scanners, &IaCScanner{})
		default:
			return nil, fmt.Errorf("unknown scanner: %s (valid: secrets, iac)", name)
		}
	}
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners specified")
	}
	return scanners, nil
}
