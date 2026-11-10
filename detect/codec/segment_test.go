package codec

import (
	"testing"
)

func TestCurrentLineEmptySegmentOnNewline(t *testing.T) {
	// An empty decoded range starting on a newline moves start past end
	// (start = i + 1 skips the newline); the slice must be clamped
	// instead of panicking. See PR #2346 review.
	raw := "abc\ndef"
	segments := []*EncodedSegment{{decoded: startEnd{start: 3, end: 3}}}
	if got := CurrentLine(segments, raw); got != "" {
		t.Fatalf("expected empty line, got %q", got)
	}
}

func TestCurrentLineSkipsPreviousLineNewline(t *testing.T) {
	// Non-empty range: the reported line starts after the previous
	// line's newline instead of including it.
	raw := "abc\ndef"
	segments := []*EncodedSegment{{decoded: startEnd{start: 4, end: 7}}}
	if got := CurrentLine(segments, raw); got != "def" {
		t.Fatalf("expected %q, got %q", "def", got)
	}
}
