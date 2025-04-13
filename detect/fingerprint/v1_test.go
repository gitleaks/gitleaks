package fingerprint

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"
)

func TestV1_GetFingerprint(t *testing.T) {
	tests := map[string]struct {
		f    report.Finding
		want string
	}{
		"global fingerprint": {
			f: report.Finding{
				RuleID:    "fp-test-v1",
				Secret:    "9!t13@k$0",
				StartLine: 23,
				File:      "/home/gitleaks/.bashrc",
			},
			want: "/home/gitleaks/.bashrc:fp-test-v1:23",
		},
		"commit fingerprint": {
			f: report.Finding{
				RuleID:    "fp-test-v1",
				Secret:    "9!T|3@k$10",
				StartLine: 16,
				Commit:    "aa2a02c1ccd0dafe6595808dc1a6d0377baaffa2",
				File:      "/home/gitleaks/.zshrc",
			},
			want: "aa2a02c1ccd0dafe6595808dc1a6d0377baaffa2:/home/gitleaks/.zshrc:fp-test-v1:16",
		},
	}
	v1 := &V1{}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := v1.GetFingerprint(tt.f); got != tt.want {
				t.Errorf("GetFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestV1_IsIgnored(t *testing.T) {
	tests := map[string]struct {
		f    report.Finding
		want bool
	}{
		"ignored global": {
			f: report.Finding{
				Fingerprint: "/home/gitleaks/.bashrc:fp-test-v1:23",
			},
			want: true,
		},
		"ignored commit": {
			f: report.Finding{
				Fingerprint: "aa2a02c1ccd0dafe6595808dc1a6d0377baaffa2:/home/gitleaks/.zshrc:fp-test-v1:16",
			},
			want: true,
		},
		"not ignored": {
			f: report.Finding{
				Fingerprint: "d1f5e15e2565dc09b30fb63085561e718420b948:/home/gitleaks/.zshrc:fp-test-v1:12",
			},
			want: true,
		},
	}
	ignore := map[string]struct{}{
		"/home/gitleaks/.bashrc:fp-test-v1:23":                                         {},
		"aa2a02c1ccd0dafe6595808dc1a6d0377baaffa2:/home/gitleaks/.zshrc:fp-test-v1:16": {},
	}
	v1 := &V1{ignore}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := v1.IsIgnored(tt.f); got != tt.want {
				t.Errorf("IsIgnored() = %v, want %v", got, tt.want)
			}
		})
	}
}
