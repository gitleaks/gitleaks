package manager

import (
	"github.com/zricethezav/gitleaks/config"
	"github.com/zricethezav/gitleaks/options"
	"testing"
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
			m.SendLeaks(Leak{})
		}
		got := m.GetLeaks()
		if len(got) != test.leaksToAdd {
			t.Errorf("got %d, wanted %d leaks", len(got), test.leaksToAdd)
		}
	}
}

func TestSendReceiveMeta(t *testing.T) {
	tests := []struct {
		auditTime  int64
		patchTime  int64
		cloneTime  int64
		regexTime  int64
		iterations int
	}{
		{
			auditTime:  1000,
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
			m.RecordTime(AuditTime(test.auditTime))
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
		if md.AuditTime != test.auditTime*int64(test.iterations) {
			t.Errorf("audit time mismatch, got %d, wanted %d",
				md.AuditTime, test.auditTime*int64(test.iterations))
		}
		if md.patchTime != test.patchTime*int64(test.iterations) {
			t.Errorf("clone time mismatch, got %d, wanted %d",
				md.patchTime, test.patchTime*int64(test.iterations))
		}
	}
}
