package codec

import (
	"fmt"
)

// startEnd represents the start and end of some data. It mainly exists as a
// helper when referencing the values
type startEnd struct {
	start int
	end   int
}

// sub subtracts the values of two startEnds
func (s startEnd) sub(o startEnd) startEnd {
	return startEnd{
		s.start - o.start,
		s.end - o.end,
	}
}

// add adds the values of two startEnds
func (s startEnd) add(o startEnd) startEnd {
	return startEnd{
		s.start + o.start,
		s.end + o.end,
	}
}

// overlaps returns true if two startEnds overlap
func (s startEnd) overlaps(o startEnd) bool {
	return o.start <= s.end && o.end >= s.start
}

// contains returns true if the other is fully contained within this one
func (s startEnd) contains(o startEnd) bool {
	return s.start <= o.start && o.end <= s.end
}

// overflow returns a startEnd that tells how much the other goes outside the
// bounds of this one
func (s startEnd) overflow(o startEnd) startEnd {
	return s.merge(o).sub(s)
}

// merge takes two start/ends and returns a single one that encompasses both
func (s startEnd) merge(o startEnd) startEnd {
	return startEnd{
		min(s.start, o.start),
		max(s.end, o.end),
	}
}

// String returns a string representation for clearer debugging
func (s startEnd) String() string {
	return fmt.Sprintf("[%d,%d]", s.start, s.end)
}
