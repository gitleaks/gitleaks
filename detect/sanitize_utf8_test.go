package detect

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeUTF8(t *testing.T) {
	valid := "secret_key=z1Pdn06b3TnpG/9Gwj3ppPSOlAsu08Qw29PUW+eB"
	assert.Equal(t, valid, sanitizeUTF8(valid))
	assert.Equal(t, "héllo", sanitizeUTF8("héllo"))

	invalid := "secret_key\xd3\x00\x93(z1Pdn06b3TnpG/9Gwj3ppPSOlAsu08Qw29PUW+eB"
	got := sanitizeUTF8(invalid)

	assert.True(t, utf8.ValidString(got), "sanitized input must be valid UTF-8")
	assert.Equal(t, len(invalid), len(got), "replacement must preserve byte offsets")
	assert.Equal(t, "secret_key?\x00?(z1Pdn06b3TnpG/9Gwj3ppPSOlAsu08Qw29PUW+eB", got)
}
