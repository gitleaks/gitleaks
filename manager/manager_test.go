package manager

import (
	"crypto/rand"
	"fmt"
	"io"
	"regexp"
	"testing"

	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/options"
)

// TODO
// add more substantial tests... but since literally every pkg uses manager
// these tests are kind of redundant
func TestSendReceiveLeaks(t *testing.T) {

	tests := []struct {
		leaksToAdd int
		goRoutines int
	}{
		{
			leaksToAdd: 10,
		},
		{
			leaksToAdd: 1000,
		},
	}
	for _, test := range tests {
		opts := options.Options{}
		cfg, _ := config.NewConfig(opts)
		m, _ := NewManager(opts, cfg)

		for i := 0; i < test.leaksToAdd; i++ {
			// we are testing the sync of sending/receiving leaks so we need
			// the hash generation in sendLeaks to be unique for each iteration
			// so I'm just setting the offender string as a uuid
			m.SendLeaks(Leak{Offender: newUUID()})
		}
		got := m.GetLeaks()
		if len(got) != test.leaksToAdd {
			t.Errorf("got %d, wanted %d leaks", len(got), test.leaksToAdd)
		}
	}
}

func TestSendReceiveMeta(t *testing.T) {
	tests := []struct {
		scanTime   int64
		patchTime  int64
		cloneTime  int64
		regexTime  int64
		iterations int
	}{
		{
			scanTime:   1000,
			patchTime:  1000,
			cloneTime:  1000,
			regexTime:  1000,
			iterations: 100,
		},
	}
	for _, test := range tests {
		opts := options.Options{}
		cfg, _ := config.NewConfig(opts)
		m, _ := NewManager(opts, cfg)

		for i := 0; i < test.iterations; i++ {
			m.RecordTime(ScanTime(test.scanTime))
			m.RecordTime(PatchTime(test.patchTime))
			m.RecordTime(CloneTime(test.cloneTime))
			m.RecordTime(RegexTime{
				Regex: "regex",
				Time:  test.regexTime,
			})
			m.RecordTime(RegexTime{
				Regex: "regex2",
				Time:  test.regexTime,
			})
		}
		md := m.GetMetadata()
		if md.cloneTime != test.cloneTime*int64(test.iterations) {
			t.Errorf("clone time mismatch, got %d, wanted %d",
				md.cloneTime, test.cloneTime*int64(test.iterations))
		}
		if md.ScanTime != test.scanTime*int64(test.iterations) {
			t.Errorf("scan time mismatch, got %d, wanted %d",
				md.ScanTime, test.scanTime*int64(test.iterations))
		}
		if md.patchTime != test.patchTime*int64(test.iterations) {
			t.Errorf("clone time mismatch, got %d, wanted %d",
				md.patchTime, test.patchTime*int64(test.iterations))
		}
	}
}

func TestMergingConfiguration(t *testing.T) {
	testRegexA, _ := regexp.Compile("a")
	testRegexB, _ := regexp.Compile("b")

	allowListA := config.AllowList{
		Description: "Test Description",
		Commits:     []string{"a"},
		Files:       []*regexp.Regexp{testRegexA},
		Paths:       []*regexp.Regexp{testRegexA},
		Regexes:     []*regexp.Regexp{testRegexA},
		Repos:       []*regexp.Regexp{testRegexA},
	}

	allowListB := config.AllowList{
		Description: "Test Description",
		Commits:     []string{"b"},
		Files:       []*regexp.Regexp{testRegexB},
		Paths:       []*regexp.Regexp{testRegexB},
		Regexes:     []*regexp.Regexp{testRegexB},
		Repos:       []*regexp.Regexp{testRegexB},
	}

	ruleA := config.Rule{Description: "a"}
	ruleB := config.Rule{Description: "b"}

	rulesA := []config.Rule{ruleA}
	rulesB := []config.Rule{ruleB}

	cfgA := config.Config{
		Rules:     rulesA,
		Allowlist: allowListA,
	}

	cfgB := config.Config{
		Rules:     rulesB,
		Allowlist: allowListB,
	}

	m, _ := NewManager(options.Options{}, cfgA)

	cfgMerged := m.MergeConfig(cfgB)

	if !(len(cfgMerged.Rules) == 2) {
		t.Errorf("Length of Merged Rules = %d; want 2", len(cfgMerged.Rules))
	}

	if !(len(cfgMerged.Allowlist.Commits) == 2) {
		t.Errorf("Length of Merged Allowed Commits = %d; want 2", len(cfgMerged.Allowlist.Commits))
	}

	if !(len(cfgMerged.Allowlist.Files) == 2) {
		t.Errorf("Length of Merged Allowed Files = %d; want 2", len(cfgMerged.Allowlist.Files))
	}

	if !(len(cfgMerged.Allowlist.Paths) == 2) {
		t.Errorf("Length of Merged Allowed Paths = %d; want 2", len(cfgMerged.Allowlist.Paths))
	}

	if !(len(cfgMerged.Allowlist.Regexes) == 2) {
		t.Errorf("Length of Merged Allowed Regexes = %d; want 2", len(cfgMerged.Allowlist.Regexes))
	}

	if !(len(cfgMerged.Allowlist.Repos) == 2) {
		t.Errorf("Length of Merged Allowed Repos = %d; want 2", len(cfgMerged.Allowlist.Repos))
	}

	if cfgMerged.Allowlist.Description != "Merged Configuration" {
		t.Errorf("Allow List Description is = \"%s\"; want \"Merged Configuration\"", cfgMerged.Allowlist.Description)
	}

}

// newUUID generates a random UUID according to RFC 4122
// Ripped from https://play.golang.org/p/4FkNSiUDMg
func newUUID() string {
	uuid := make([]byte, 16)
	io.ReadFull(rand.Reader, uuid)
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}
