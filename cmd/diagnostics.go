package cmd

import (
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"

	"github.com/zricethezav/gitleaks/v8/logging"
)

// DiagnosticsManager manages various types of diagnostics
type DiagnosticsManager struct {
	Enabled      bool
	DiagTypes    []string
	OutputDir    string
	cpuProfile   *os.File
	memProfile   string
	traceProfile *os.File
}

// NewDiagnosticsManager creates a new DiagnosticsManager instance
func NewDiagnosticsManager(diagnosticsFlag string, diagnosticsDir string) (*DiagnosticsManager, error) {
	if diagnosticsFlag == "" {
		return &DiagnosticsManager{Enabled: false}, nil
	}

	dm := &DiagnosticsManager{
		Enabled:   true,
		DiagTypes: strings.Split(diagnosticsFlag, ","),
		OutputDir: diagnosticsDir,
	}

	if diagnosticsFlag == "http" {
		if len(diagnosticsDir) != 0 {
			return nil, errors.New("the diagnostics directory should not be set in http mode")
		}

		return dm, nil
	}

	// If no output directory is specified, use the current directory
	if dm.OutputDir == "" {
		var err error
		dm.OutputDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		logging.Debug().Msgf("No diagnostics directory specified, using current directory: %s", dm.OutputDir)
	}

	// Create the output directory if it doesn't exist
	if err := os.MkdirAll(dm.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create diagnostics directory: %w", err)
	}

	// Make sure the output directory is absolute
	if !filepath.IsAbs(dm.OutputDir) {
		absPath, err := filepath.Abs(dm.OutputDir)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for diagnostics directory: %w", err)
		}
		dm.OutputDir = absPath
	}

	logging.Debug().Msgf("Diagnostics enabled: %s", strings.Join(dm.DiagTypes, ","))
	logging.Debug().Msgf("Diagnostics output directory: %s", dm.OutputDir)

	return dm, nil
}

// StartDiagnostics starts all enabled diagnostics
func (dm *DiagnosticsManager) StartDiagnostics() error {
	if !dm.Enabled {
		return nil
	}

	var err error

	for _, diagType := range dm.DiagTypes {
		diagType = strings.TrimSpace(diagType)
		switch diagType {
		case "cpu":
			if err = dm.StartCPUProfile(); err != nil {
				return err
			}
		case "mem":
			if err = dm.SetupMemoryProfile(); err != nil {
				return err
			}
		case "trace":
			if err = dm.StartTraceProfile(); err != nil {
				return err
			}
		case "http":
			if err = dm.StartHttpHandler(); err != nil {
				return err
			}
		default:
			logging.Warn().Msgf("Unknown diagnostics type: %s", diagType)
		}
	}

	return nil
}

// StopDiagnostics stops all started diagnostics
func (dm *DiagnosticsManager) StopDiagnostics() {
	if !dm.Enabled {
		return
	}

	logging.Debug().Msg("Stopping diagnostics and writing profiling data...")

	for _, diagType := range dm.DiagTypes {
		diagType = strings.TrimSpace(diagType)
		switch diagType {
		case "cpu":
			dm.StopCPUProfile()
		case "mem":
			dm.WriteMemoryProfile()
		case "trace":
			dm.StopTraceProfile()
		case "http":
			// No need to stop the http one
		}
	}
}

func (dm *DiagnosticsManager) StartHttpHandler() error {
	if len(dm.DiagTypes) > 1 {
		return errors.New("other diagnostics modes should not be enabled when http mode is enabled")
	}

	go func() {
		logging.Error().Err(http.ListenAndServe("localhost:6060", nil)).Send()
	}()

	logging.Info().Str("url", "http://localhost:6060/debug/pprof/").Msg("Diagnostics server started")
	return nil
}

// StartCPUProfile starts CPU profiling
func (dm *DiagnosticsManager) StartCPUProfile() error {
	cpuProfilePath := filepath.Join(dm.OutputDir, "cpu.pprof")
	f, err := os.Create(cpuProfilePath)
	if err != nil {
		return fmt.Errorf("could not create CPU profile at %s: %w", cpuProfilePath, err)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("could not start CPU profile: %w", err)
	}

	dm.cpuProfile = f
	return nil
}

// StopCPUProfile stops CPU profiling
func (dm *DiagnosticsManager) StopCPUProfile() {
	if dm.cpuProfile != nil {
		pprof.StopCPUProfile()
		if err := dm.cpuProfile.Close(); err != nil {
			logging.Error().Err(err).Msg("Error closing CPU profile file")
		}
		logging.Info().Msgf("CPU profile written to: %s", dm.cpuProfile.Name())
		dm.cpuProfile = nil
	}
}

// SetupMemoryProfile sets up memory profiling to be written when StopDiagnostics is called
func (dm *DiagnosticsManager) SetupMemoryProfile() error {
	memProfilePath := filepath.Join(dm.OutputDir, "mem.pprof")
	dm.memProfile = memProfilePath
	return nil
}

// WriteMemoryProfile writes the memory profile to disk
func (dm *DiagnosticsManager) WriteMemoryProfile() {
	if dm.memProfile == "" {
		return
	}

	f, err := os.Create(dm.memProfile)
	if err != nil {
		logging.Error().Err(err).Msgf("Could not create memory profile at %s", dm.memProfile)
		return
	}

	// Get memory profile
	runtime.GC() // Run GC before taking the memory profile
	if err := pprof.WriteHeapProfile(f); err != nil {
		logging.Error().Err(err).Msg("Could not write memory profile")
	} else {
		logging.Info().Msgf("Memory profile written to: %s", dm.memProfile)
	}

	if err := f.Close(); err != nil {
		logging.Error().Err(err).Msg("Error closing memory profile file")
	}

	dm.memProfile = ""
}

// StartTraceProfile starts execution tracing
func (dm *DiagnosticsManager) StartTraceProfile() error {
	traceProfilePath := filepath.Join(dm.OutputDir, "trace.out")
	f, err := os.Create(traceProfilePath)
	if err != nil {
		return fmt.Errorf("could not create trace profile at %s: %w", traceProfilePath, err)
	}

	if err := trace.Start(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("could not start trace profile: %w", err)
	}

	dm.traceProfile = f
	return nil
}

// StopTraceProfile stops execution tracing
func (dm *DiagnosticsManager) StopTraceProfile() {
	if dm.traceProfile != nil {
		trace.Stop()
		if err := dm.traceProfile.Close(); err != nil {
			logging.Error().Err(err).Msg("Error closing trace profile file")
		}
		logging.Info().Msgf("Trace profile written to: %s", dm.traceProfile.Name())
		dm.traceProfile = nil
	}
}
