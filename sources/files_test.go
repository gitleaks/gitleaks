package sources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFiles_withUnreadableFilesError(t *testing.T) {
	t.Run("no unreadable files leaves walkErr untouched", func(t *testing.T) {
		s := &Files{}
		walkErr := errors.New("walk boom")
		assert.Equal(t, walkErr, s.withUnreadableFilesError(walkErr))
		assert.NoError(t, s.withUnreadableFilesError(nil))
	})

	t.Run("unreadable files with no walk error", func(t *testing.T) {
		s := &Files{}
		s.unreadableFiles.Add(3)
		err := s.withUnreadableFilesError(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "3 file(s) could not be opened")
	})

	t.Run("unreadable files combine with a walk error", func(t *testing.T) {
		s := &Files{}
		s.unreadableFiles.Add(1)
		walkErr := errors.New("walk boom")
		err := s.withUnreadableFilesError(walkErr)
		require.Error(t, err)
		assert.ErrorIs(t, err, walkErr)
		assert.Contains(t, err.Error(), "1 file(s) could not be opened")
	})
}
