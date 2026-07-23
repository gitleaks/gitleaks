package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
	"github.com/zricethezav/gitleaks/v8/version"
)

func init() {
	rootCmd.AddCommand(mcpCmd)
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "start an MCP server exposing gitleaks tools",
	Long: `Start a Model Context Protocol (MCP) server that exposes gitleaks
scanning capabilities as tools. The server communicates via stdio and can be
used with MCP-compatible clients such as coding agents and AI assistants.`,
	Run: runMCP,
}

// allowedLogOpts is the set of git log flags considered safe to pass through
// from MCP clients. Flags not in this list are rejected to prevent injection
// of arbitrary git options (e.g. --exec, --output).
var allowedLogOpts = map[string]bool{
	"--since":          true,
	"--until":          true,
	"--after":          true,
	"--before":         true,
	"--author":         true,
	"--committer":      true,
	"--grep":           true,
	"--all":            true,
	"--branches":       true,
	"--tags":           true,
	"--remotes":        true,
	"--first-parent":   true,
	"--merges":         true,
	"--no-merges":      true,
	"--max-count":      true,
	"--skip":           true,
	"--ancestry-path":  true,
	"-n":               true,
}

// validateLogOpts checks that every flag in logOpts is in the allowlist.
// Returns an error describing the first rejected flag, or nil if all are safe.
func validateLogOpts(logOpts string) error {
	if logOpts == "" {
		return nil
	}
	parts := strings.Fields(logOpts)
	for _, part := range parts {
		if !strings.HasPrefix(part, "-") {
			// Positional arg (e.g. a value for --since), allow it.
			continue
		}
		// Handle --flag=value by splitting on '='.
		flag := part
		if idx := strings.Index(part, "="); idx != -1 {
			flag = part[:idx]
		}
		if !allowedLogOpts[flag] {
			return fmt.Errorf("log_opts contains disallowed flag %q; only date/author/branch filter flags are permitted", flag)
		}
	}
	return nil
}

func runMCP(_ *cobra.Command, _ []string) {
	s := server.NewMCPServer(
		"gitleaks",
		version.Version,
		server.WithToolCapabilities(false),
	)

	// Register tools
	s.AddTool(scanDirectoryTool(), handleScanDirectory)
	s.AddTool(scanGitTool(), handleScanGit)

	if err := server.ServeStdio(s); err != nil {
		logging.Fatal().Err(err).Msg("MCP server error")
	}
}

func boolPtr(b bool) *bool { return &b }

func scanDirectoryTool() mcp.Tool {
	return mcp.NewTool("scan_directory",
		mcp.WithDescription("Scan a directory or file for secrets using gitleaks. Returns any findings as JSON."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the directory or file to scan"),
		),
		mcp.WithNumber("max_target_megabytes",
			mcp.Description("Skip files larger than this size in megabytes (default 0, no limit)"),
		),
		mcp.WithBoolean("follow_symlinks",
			mcp.Description("Follow symlinks when scanning (default false)"),
		),
		mcp.WithNumber("max_decode_depth",
			mcp.Description("Maximum recursive decoding depth (default 5)"),
		),
		mcp.WithNumber("max_archive_depth",
			mcp.Description("Maximum nested archive scanning depth (default 0, no archive traversal)"),
		),
		mcp.WithNumber("redact",
			mcp.Description("Redact secrets from output. Value from 0-100 as percentage (default 100, full redaction). Set to 0 to disable redaction."),
		),
	)
}

func scanGitTool() mcp.Tool {
	return mcp.NewTool("scan_git",
		mcp.WithDescription("Scan a git repository's commit history for secrets using gitleaks. Returns any findings as JSON."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the git repository to scan"),
		),
		mcp.WithString("log_opts",
			mcp.Description("Additional git log options (e.g. '--since=2024-01-01'). Only date, author, and branch filter flags are allowed."),
		),
		mcp.WithBoolean("staged",
			mcp.Description("Scan only staged changes (default false)"),
		),
		mcp.WithBoolean("pre_commit",
			mcp.Description("Scan using git diff for pre-commit checking (default false)"),
		),
		mcp.WithNumber("max_decode_depth",
			mcp.Description("Maximum recursive decoding depth (default 5)"),
		),
		mcp.WithNumber("max_archive_depth",
			mcp.Description("Maximum nested archive scanning depth (default 0, no archive traversal)"),
		),
		mcp.WithNumber("redact",
			mcp.Description("Redact secrets from output. Value from 0-100 as percentage (default 100, full redaction). Set to 0 to disable redaction."),
		),
	)
}

// loadMCPConfig loads the gitleaks config for a given source path.
// It checks GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML env vars first,
// then source-local .gitleaks.toml, and falls back to the built-in default.
// Returns an error if config loading or parsing fails.
func loadMCPConfig(source string) (config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")

	loaded := false

	// Check GITLEAKS_CONFIG env var first (points to a file path).
	if envPath := os.Getenv("GITLEAKS_CONFIG"); envPath != "" {
		v.SetConfigFile(envPath)
		logging.Debug().Msgf("using gitleaks config from GITLEAKS_CONFIG env var: %s", envPath)
		if err := v.ReadInConfig(); err != nil {
			return config.Config{}, fmt.Errorf("failed to load config from GITLEAKS_CONFIG (%s): %w", envPath, err)
		}
		loaded = true
	} else if envContent := os.Getenv("GITLEAKS_CONFIG_TOML"); envContent != "" {
		// GITLEAKS_CONFIG_TOML contains inline TOML content.
		logging.Debug().Msg("using gitleaks config from GITLEAKS_CONFIG_TOML env var content")
		if err := v.ReadConfig(strings.NewReader(envContent)); err != nil {
			return config.Config{}, fmt.Errorf("failed to load config from GITLEAKS_CONFIG_TOML: %w", err)
		}
		loaded = true
	}

	if !loaded {
		// Check for {source}/.gitleaks.toml.
		localConfig := filepath.Join(source, ".gitleaks.toml")
		fileInfo, statErr := os.Stat(source)
		if statErr == nil && fileInfo.IsDir() {
			if _, err := os.Stat(localConfig); err == nil {
				logging.Debug().Msgf("using gitleaks config from %s", localConfig)
				v.AddConfigPath(source)
				v.SetConfigName(".gitleaks")
				if err := v.ReadInConfig(); err != nil {
					return config.Config{}, fmt.Errorf("failed to load config from %s: %w", localConfig, err)
				}
				loaded = true
			}
		}
	}

	if !loaded {
		// Fall back to built-in default config.
		logging.Debug().Msg("using default gitleaks config")
		if err := v.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
			return config.Config{}, fmt.Errorf("failed to load default config: %w", err)
		}
	}

	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	cfg, err := vc.Translate()
	if err != nil {
		return config.Config{}, fmt.Errorf("failed to translate config: %w", err)
	}
	return cfg, nil
}

func newMCPDetector(ctx context.Context, cfg config.Config, source string, maxDecodeDepth, maxArchiveDepth int, redact uint) *detect.Detector {
	detector := detect.NewDetectorContext(ctx, cfg)
	detector.MaxDecodeDepth = maxDecodeDepth
	detector.MaxArchiveDepth = maxArchiveDepth
	detector.Redact = redact

	// Load .gitleaksignore from the source path, matching the behavior in
	// cmd/root.go Detector().
	ignorePath := filepath.Join(source, ".gitleaksignore")
	if fileExists(ignorePath) {
		if err := detector.AddGitleaksIgnore(ignorePath); err != nil {
			logging.Warn().Err(err).Msg("could not load .gitleaksignore")
		}
	}

	return detector
}

func findingsToJSON(findings []report.Finding) (string, error) {
	if len(findings) == 0 {
		return "[]", nil
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return "", fmt.Errorf("failed to encode findings: %w", err)
	}
	return buf.String(), nil
}

func handleScanDirectory(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("path is required"), nil
	}

	maxTargetMB := 0
	if v, ok := request.GetArguments()["max_target_megabytes"]; ok {
		if n, ok := v.(float64); ok {
			maxTargetMB = int(n)
		}
	}

	followSymlinks := false
	if v, ok := request.GetArguments()["follow_symlinks"]; ok {
		if b, ok := v.(bool); ok {
			followSymlinks = b
		}
	}

	maxDecodeDepth := 5
	if v, ok := request.GetArguments()["max_decode_depth"]; ok {
		if n, ok := v.(float64); ok {
			maxDecodeDepth = int(n)
		}
	}

	maxArchiveDepth := 0
	if v, ok := request.GetArguments()["max_archive_depth"]; ok {
		if n, ok := v.(float64); ok {
			maxArchiveDepth = int(n)
		}
	}

	// Default to full redaction (100%) for MCP server output.
	// Callers must explicitly set redact=0 to get unredacted secrets.
	redact := uint(100)
	if v, ok := request.GetArguments()["redact"]; ok {
		if n, ok := v.(float64); ok {
			redact = uint(n)
		}
	}

	cfg, err := loadMCPConfig(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("config error: %v", err)), nil
	}
	detector := newMCPDetector(ctx, cfg, path, maxDecodeDepth, maxArchiveDepth, redact)

	findings, err := detector.DetectSource(
		ctx,
		&sources.Files{
			Config:          &cfg,
			FollowSymlinks:  followSymlinks,
			MaxFileSize:     maxTargetMB * 1_000_000,
			Path:            path,
			Sema:            detector.Sema,
			MaxArchiveDepth: maxArchiveDepth,
		},
	)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// Redaction is already applied by the detector's filter() in DetectContext.
	// Do not redact again here to avoid corrupting already-masked output.

	result, err := findingsToJSON(findings)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	summary := fmt.Sprintf("Scanned directory: %s\nFindings: %d\n\n%s", path, len(findings), result)
	return mcp.NewToolResultText(summary), nil
}

func handleScanGit(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("path is required"), nil
	}

	logOpts := ""
	if v, ok := request.GetArguments()["log_opts"]; ok {
		if s, ok := v.(string); ok {
			logOpts = s
		}
	}

	// Validate log_opts against the allowlist before passing to git.
	if err := validateLogOpts(logOpts); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid log_opts: %v", err)), nil
	}

	staged := false
	if v, ok := request.GetArguments()["staged"]; ok {
		if b, ok := v.(bool); ok {
			staged = b
		}
	}

	preCommit := false
	if v, ok := request.GetArguments()["pre_commit"]; ok {
		if b, ok := v.(bool); ok {
			preCommit = b
		}
	}

	maxDecodeDepth := 5
	if v, ok := request.GetArguments()["max_decode_depth"]; ok {
		if n, ok := v.(float64); ok {
			maxDecodeDepth = int(n)
		}
	}

	maxArchiveDepth := 0
	if v, ok := request.GetArguments()["max_archive_depth"]; ok {
		if n, ok := v.(float64); ok {
			maxArchiveDepth = int(n)
		}
	}

	// Default to full redaction (100%) for MCP server output.
	// Callers must explicitly set redact=0 to get unredacted secrets.
	redact := uint(100)
	if v, ok := request.GetArguments()["redact"]; ok {
		if n, ok := v.(float64); ok {
			redact = uint(n)
		}
	}

	cfg, err := loadMCPConfig(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("config error: %v", err)), nil
	}
	detector := newMCPDetector(ctx, cfg, path, maxDecodeDepth, maxArchiveDepth, redact)

	var (
		gitCmd   *sources.GitCmd
		findings []report.Finding
	)

	if preCommit || staged {
		gitCmd, err = sources.NewGitDiffCmdContext(ctx, path, staged)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create git diff cmd: %v", err)), nil
		}
	} else {
		gitCmd, err = sources.NewGitLogCmdContext(ctx, path, logOpts)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create git log cmd: %v", err)), nil
		}
	}

	findings, err = detector.DetectSource(
		ctx,
		&sources.Git{
			Cmd:             gitCmd,
			Config:          &detector.Config,
			Sema:            detector.Sema,
			MaxArchiveDepth: maxArchiveDepth,
		},
	)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// Redaction is already applied by the detector's filter() in DetectContext.
	// Do not redact again here to avoid corrupting already-masked output.

	result, err := findingsToJSON(findings)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	summary := fmt.Sprintf("Scanned git repo: %s\nFindings: %d\n\n%s", path, len(findings), result)
	return mcp.NewToolResultText(summary), nil
}
