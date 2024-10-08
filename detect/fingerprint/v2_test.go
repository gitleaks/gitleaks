package fingerprint

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"
)

func TestV2_GetFingerprint(t *testing.T) {
	tests := map[string]struct {
		f    report.Finding
		want string
	}{
		"short input": {
			f: report.Finding{
				RuleID:    "fp-test-v1",
				Secret:    "9!t13@k$0",
				StartLine: 23,
				File:      "/home/gitleaks/.bashrc",
			},
			want: "sha1_f848d287c6b146a5184e7da65b1fe2f444743870",
		},
		"long input": {
			f: report.Finding{
				RuleID:    "pirate-key",
				Secret:    "-----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCsPzMirIottfQ2\\nryjQmPWocSEeGo7f7Q4/tMQXHlXFzo93AGgU2t+clEj9L5loNhLVq+vk+qmnyDz5\\nQ04y8jVWyMYzzGNNrGRW/yaYqnqlKZCy1O3bmnNjV7EDbC/jE1ZLBY0U3HaSHfn6\\nS9ND8MXdgD0/ulRTWwq6vU8/w6i5tYsU7n2LLlQTl1fQ7/emO9nYcCFJezHZVa0H\\nmeWsdHwWsok0skwQYQNIzP3JF9BpR5gJT2gNge6KopDesJeLoLzaX7cUnDn+CAnn\\nLuLDwwSsIVKyVxhBFsFXPplgpaQRwmGzwEbf/Xpt9qo26w2UMgn30jsOaKlSeAX8\\ncS6ViF+tAgMBAAECggEACKRuJCP8leEOhQziUx8Nmls8wmYqO4WJJLyk5xUMUC22\\nSI4CauN1e0V8aQmxnIc0CDkFT7qc9xBmsMoF+yvobbeKrFApvlyzNyM7tEa/exh8\\nDGD/IzjbZ8VfWhDcUTwn5QE9DCoon9m1sG+MBNlokB3OVOt8LieAAREdEBG43kJu\\nyQTOkY9BGR2AY1FnAl2VZ/jhNDyrme3tp1sW1BJrawzR7Ujo8DzlVcS2geKA9at7\\n55ua5GbHz3hfzFgjVXDfnkWzId6aHypUyqHrSn1SqGEbyXTaleKTc6Pgv0PgkJjG\\nhZazWWdSuf1T5Xbs0OhAK9qraoAzT6cXXvMEvvPt6QKBgQDXcZKqJAOnGEU4b9+v\\nOdoh+nssdrIOBNMu1m8mYbUVYS1aakc1iDGIIWNM3qAwbG+yNEIi2xi80a2RMw2T\\n9RyCNB7yqCXXVKLBiwg9FbKMai6Vpk2bWIrzahM9on7AhCax/X2AeOp+UyYhFEy6\\nUFG4aHb8THscL7b515ukSuKb5QKBgQDMq+9PuaB0eHsrmL6q4vHNi3MLgijGg/zu\\nAXaPygSYAwYW8KglcuLZPvWrL6OG0+CrfmaWTLsyIZO4Uhdj7MLvX6yK7IMnagvk\\nL3xjgxSklEHJAwi5wFeJ8ai/1MIuCn8p2re3CbwISKpvf7Sgs/W4196P4vKvTiAz\\njcTiSYFIKQKBgCjMpkS4O0TakMlGTmsFnqyOneLmu4NyIHgfPb9cA4n/9DHKLKAT\\noaWxBPgatOVWs7RgtyGYsk+XubHkpC6f3X0+15mGhFwJ+CSE6tN+l2iF9zp52vqP\\nQwkjzm7+pdhZbmaIpcq9m1K+9lqPWJRz/3XXuqi+5xWIZ7NaxGvRjqaNAoGAdK2b\\nutZ2y48XoI3uPFsuP+A8kJX+CtWZrlE1NtmS7tnicdd19AtfmTuUL6fz0FwfW4Su\\nlQZfPT/5B339CaEiq/Xd1kDor+J7rvUHM2+5p+1A54gMRGCLRv92FQ4EON0RC1o9\\nm2I4SHysdO3XmjmdXmfp4BsgAKJIJzutvtbqlakCgYB+Cb10z37NJJ+WgjDt+yT2\\nyUNH17EAYgWXryfRgTyi2POHuJitd64Xzuy6oBVs3wVveYFM6PIKXlj8/DahYX5I\\nR2WIzoCNLL3bEZ+nC6Jofpb4kspoAeRporj29SgesK6QBYWHWX2H645RkRGYGpDo\\n51gjy9m/hSNqBbH2zmh04A==\\n-----END PRIVATE KEY-----\\n",
				StartLine: 5,
				File:      "/home/gitleaks/service-account.json",
			},
			want: "sha1_e661fc3fc338ecd2df220cee6a36fa6ec10a3c4e",
		},
	}
	v2 := &V2{}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := v2.GetFingerprint(tt.f); got != tt.want {
				t.Errorf("GetFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestV2_IsIgnored(t *testing.T) {
	tests := map[string]struct {
		f    report.Finding
		want bool
	}{}
	ignore := map[string]struct{}{}
	v2 := &V2{ignore}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := v2.IsIgnored(tt.f); got != tt.want {
				t.Errorf("IsIgnored() = %v, want %v", got, tt.want)
			}
		})
	}
}
