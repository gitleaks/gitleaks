package sources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathGlobMatch(t *testing.T) {
	t.Run("PathGlobMatch", func(t *testing.T) {
		assert.False(t, PathGlobMatch("a/*/c", "a/b/d/c"))   // * matches only one segment
		assert.False(t, PathGlobMatch("a/b/c", "a/b/d"))     // exact match required
		assert.True(t, PathGlobMatch("**", "a"))             // match anything
		assert.True(t, PathGlobMatch("**", "a/b/d"))         // match anything
		assert.True(t, PathGlobMatch("a/**", "a/b/d/e/c"))   // ** matches till the end
		assert.True(t, PathGlobMatch("a/**/c", "a/b/d/e/c")) // ** matches multiple segments
		assert.True(t, PathGlobMatch("a/**/d", "a/b/c/d"))   // ** matches intermediate segments
		assert.True(t, PathGlobMatch("a/*/c", "a/b/c"))      // * matches one segment
		assert.True(t, PathGlobMatch("a/b/c", "a/b/c"))      // exact match
	})
}
