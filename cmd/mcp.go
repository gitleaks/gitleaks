package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func scanDirectoryTool() mcp.Tool {
	return mcp.NewTool("scan_directory",
		mcp.WithDescription("Scan a directory or file for secrets using gitleaks. Returns any findings as JSON."),
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
		mcp.WithNumber("redact",
			mcp.Description("Redact secrets from output. Value from 0-100 as percentage (default 0, no redaction)"),
		),
	)
}

func scanGitTool() mcp.Tool {
	return mcp.NewTool("scan_git",
		mcp.WithDescription("Scan a git repository's commit history for secrets using gitleaks. Returns any findings as JSON."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the git repository to scan"),
		),
		mcp.WithString("log_opts",
			mcp.Description("Additional git log options (e.g. '--since=2024-01-01')"),
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
		mcp.WithNumber("redact",
			mcp.Description("Redact secrets from output. Value from 0-100 as percentage (default 0, no redaction)"),
		),
	)
}

// loadMCPConfig loads the gitleaks config for a given source path.
func loadMCPConfig(source string) config.Config {
	v := viper.New()
	v.SetConfigType("toml")

	if err := v.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
		logging.Warn().Err(err).Msg("failed to load default config")
		return config.Config{}
	}

	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		logging.Warn().Err(err).Msg("failed to unmarshal config")
		return config.Config{}
	}

	cfg, err := vc.Translate()
	if err != nil {
		logging.Warn().Err(err).Msg("failed to translate config")
		return config.Config{}
	}
	return cfg
}

func newMCPDetector(ctx context.Context, cfg config.Config, maxDecodeDepth int, redact uint) *detect.Detector {
	detector := detect.NewDetectorContext(ctx, cfg)
	detector.MaxDecodeDepth = maxDecodeDepth
	if redact > 0 {
		detector.Redact = redact
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

	var redact uint
	if v, ok := request.GetArguments()["redact"]; ok {
		if n, ok := v.(float64); ok {
			redact = uint(n)
		}
	}

	cfg := loadMCPConfig(path)
	detector := newMCPDetector(ctx, cfg, maxDecodeDepth, redact)

	findings, err := detector.DetectSource(
		ctx,
		&sources.Files{
			Config:         &cfg,
			FollowSymlinks: followSymlinks,
			MaxFileSize:    maxTargetMB * 1_000_000,
			Path:           path,
			Sema:           detector.Sema,
		},
	)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// Redact if requested
	if redact > 0 {
		for i := range findings {
			findings[i].Redact(redact)
		}
	}

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

	var redact uint
	if v, ok := request.GetArguments()["redact"]; ok {
		if n, ok := v.(float64); ok {
			redact = uint(n)
		}
	}

	cfg := loadMCPConfig(path)
	detector := newMCPDetector(ctx, cfg, maxDecodeDepth, redact)

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
			Cmd:    gitCmd,
			Config: &detector.Config,
			Sema:   detector.Sema,
		},
	)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// Redact if requested
	if redact > 0 {
		for i := range findings {
			findings[i].Redact(redact)
		}
	}

	result, err := findingsToJSON(findings)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	summary := fmt.Sprintf("Scanned git repo: %s\nFindings: %d\n\n%s", path, len(findings), result)
	return mcp.NewToolResultText(summary), nil
}
