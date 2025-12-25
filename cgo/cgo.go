package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// NOTE: The gitleaks config package uses global state via viper and extendDepth.
// For use as a shared library, we serialize config operations with a mutex.
var configMu sync.Mutex

// Opaque detector handles (avoid passing Go pointers through cgo).
var (
	handleMu   sync.Mutex
	nextHandle uint64 = 1
	detectors         = map[uint64]*detect.Detector{}
)

func setErr(outErr **C.char, err error) {
	if outErr == nil {
		return
	}
	if err == nil {
		*outErr = nil
		return
	}
	*outErr = C.CString(err.Error())
}

//export GitleaksFreeString
func GitleaksFreeString(s *C.char) {
	if s == nil {
		return
	}
	C.free(unsafe.Pointer(s))
}

//export GitleaksCreateDefaultDetector
func GitleaksCreateDefaultDetector(outErr **C.char) C.ulonglong {
	configMu.Lock()
	d, err := detect.NewDetectorDefaultConfig()
	configMu.Unlock()
	if err != nil {
		setErr(outErr, err)
		return 0
	}
	// Library mode: disable decoding by default (decoding is a CLI feature).
	d.MaxDecodeDepth = 0
	handleMu.Lock()
	h := nextHandle
	nextHandle++
	detectors[h] = d
	handleMu.Unlock()
	setErr(outErr, nil)
	return C.ulonglong(h)
}

//export GitleaksCreateDetectorFromToml
func GitleaksCreateDetectorFromToml(configToml *C.char, outErr **C.char) C.ulonglong {
	if configToml == nil {
		setErr(outErr, errors.New("configToml is NULL"))
		return 0
	}
	cfgStr := C.GoString(configToml)
	cfgStr = strings.TrimSpace(cfgStr)
	if cfgStr == "" {
		setErr(outErr, errors.New("configToml is empty"))
		return 0
	}

	// Parse TOML using viper (mirrors CLI behavior).
	configMu.Lock()
	defer configMu.Unlock()

	// WARNING: config.Translate uses package-level viper state for extending.
	// To keep behavior consistent, we temporarily configure the global viper.
	// This is guarded by configMu.
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(cfgStr)); err != nil {
		setErr(outErr, err)
		return 0
	}

	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		setErr(outErr, err)
		return 0
	}

	cfg, err := vc.Translate()
	if err != nil {
		setErr(outErr, err)
		return 0
	}

	d := detect.NewDetector(cfg)
	// Library mode: disable decoding by default (decoding is a CLI feature).
	d.MaxDecodeDepth = 0

	handleMu.Lock()
	h := nextHandle
	nextHandle++
	detectors[h] = d
	handleMu.Unlock()

	setErr(outErr, nil)
	return C.ulonglong(h)
}

//export GitleaksFreeDetector
func GitleaksFreeDetector(handle C.ulonglong) {
	h := uint64(handle)
	handleMu.Lock()
	delete(detectors, h)
	handleMu.Unlock()
}

func getDetector(handle C.ulonglong) (*detect.Detector, error) {
	h := uint64(handle)
	handleMu.Lock()
	d := detectors[h]
	handleMu.Unlock()
	if d == nil {
		return nil, errors.New("invalid detector handle")
	}
	return d, nil
}

func findingsToPayload(findings []report.Finding) FindingsPayload {
	out := FindingsPayload{Findings: make([]FindingPayload, 0, len(findings))}
	for _, f := range findings {
		out.Findings = append(out.Findings, FindingPayload{
			RuleID:       f.RuleID,
			Description:  f.Description,
			Match:        f.Match,
			Secret:       f.Secret,
			Tags:         f.Tags,
			SecretStart:  f.SecretStart,
			SecretEnd:    f.SecretEnd,
			StartLine:    f.StartLine,
			EndLine:      f.EndLine,
			StartColumn:  f.StartColumn,
			EndColumn:    f.EndColumn,
			File:         f.File,
			Commit:       f.Commit,
		})
	}
	return out
}

//export GitleaksDetectString
func GitleaksDetectString(handle C.ulonglong, text *C.char, filePath *C.char, outErr **C.char) *C.char {
	d, err := getDetector(handle)
	if err != nil {
		setErr(outErr, err)
		return nil
	}
	if text == nil {
		setErr(outErr, errors.New("text is NULL"))
		return nil
	}

	raw := C.GoString(text)
	fp := ""
	if filePath != nil {
		fp = C.GoString(filePath)
	}

	findings := d.Detect(detect.Fragment{
		Raw:      raw,
		FilePath: fp,
	})

	payload := findingsToPayload(findings)
	b, err := json.Marshal(payload)
	if err != nil {
		setErr(outErr, err)
		return nil
	}
	setErr(outErr, nil)
	return C.CString(string(b))
}

//export GitleaksDetectBytes
func GitleaksDetectBytes(handle C.ulonglong, data *C.uchar, dataLen C.int, filePath *C.char, outErr **C.char) *C.char {
	d, err := getDetector(handle)
	if err != nil {
		setErr(outErr, err)
		return nil
	}
	if data == nil && dataLen > 0 {
		setErr(outErr, errors.New("data is NULL"))
		return nil
	}

	var raw string
	if dataLen > 0 {
		raw = string(C.GoBytes(unsafe.Pointer(data), dataLen))
	}
	fp := ""
	if filePath != nil {
		fp = C.GoString(filePath)
	}

	findings := d.Detect(detect.Fragment{
		Raw:      raw,
		FilePath: fp,
	})

	payload := findingsToPayload(findings)
	b, err := json.Marshal(payload)
	if err != nil {
		setErr(outErr, err)
		return nil
	}
	setErr(outErr, nil)
	return C.CString(string(b))
}


