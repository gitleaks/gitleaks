package sources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathGlobMatch(t *testing.T) {
	t.Run("pathGlobMatch", func(t *testing.T) {
		assert.False(t, pathGlobMatch("a/*/c", "a/b/d/c"))                // * matches only one segment
		assert.False(t, pathGlobMatch("a/b/c", "a/b/d"))                  // exact match required
		assert.True(t, pathGlobMatch("**", "a"))                          // match anything
		assert.True(t, pathGlobMatch("**", "a/b/d"))                      // match anything
		assert.True(t, pathGlobMatch("a/**", "a/b/d/e/c"))                // ** matches till the end
		assert.True(t, pathGlobMatch("a/**/c", "a/b/d/e/c"))              // ** matches multiple segments
		assert.True(t, pathGlobMatch("a/**/d", "a/b/c/d"))                // ** matches intermediate segments
		assert.True(t, pathGlobMatch("a/*/c", "a/b/c"))                   // * matches one segment
		assert.True(t, pathGlobMatch("a/b/c", "a/b/c"))                   // exact match
		assert.True(t, pathGlobMatch("a/**/e", "a/b/c/d/e"))              // match any part of the middle of the path
		assert.True(t, pathGlobMatch("*/b/**/e", "a/b/c/d/e"))            // match any part of the middle of the path
		assert.True(t, pathGlobMatch("**/d/**/h/i", "a/b/c/d/e/f/g/h/i")) // allow any of the beginning and in the middle too
		assert.False(t, pathGlobMatch("**/d/*/h/i", "a/b/c/d/e/f/g/h/i")) // * still should only match 1 segment here
	})
}
