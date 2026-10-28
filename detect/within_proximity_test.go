package detect

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestWithinProximityColumns(t *testing.T) {
	col := func(n int) *int { return &n }
	d := &Detector{}

	tests := []struct {
		name             string
		primary, require report.Finding
		required         *config.Required
		want             bool
	}{
		{
			name:     "same line, within column distance",
			primary:  report.Finding{StartLine: 1, StartColumn: 5},
			require:  report.Finding{StartLine: 1, StartColumn: 8},
			required: &config.Required{WithinColumns: col(5)},
			want:     true,
		},
		{
			name:     "same line, beyond column distance",
			primary:  report.Finding{StartLine: 1, StartColumn: 5},
			require:  report.Finding{StartLine: 1, StartColumn: 60},
			required: &config.Required{WithinColumns: col(5)},
			want:     false,
		},
		{
			// Columns restart per line, so findings on different lines must never
			// satisfy a column-proximity constraint, even if the raw numbers are close.
			name:     "different lines never satisfy column proximity",
			primary:  report.Finding{StartLine: 1, StartColumn: 5},
			require:  report.Finding{StartLine: 300, StartColumn: 6},
			required: &config.Required{WithinColumns: col(5)},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.withinProximity(tt.primary, tt.require, tt.required); got != tt.want {
				t.Errorf("withinProximity() = %v, want %v", got, tt.want)
			}
		})
	}
}
