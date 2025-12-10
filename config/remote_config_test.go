package config

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestFetchConfig(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		wantErr    bool
		errStr     string
	}{
		{
			name:       "Successful fetch",
			statusCode: http.StatusOK,
			body:       []byte("test config"),
			wantErr:    false,
		},
		{
			name:       "Empty body",
			statusCode: http.StatusOK,
			body:       nil,
			wantErr:    true,
			errStr:     "empty response body from URL",
		},
		{
			name:       "Bad status code",
			statusCode: http.StatusNotFound,
			body:       nil,
			wantErr:    true,
			errStr:     "status code:404 returned from remote URL",
		},
	}

	ctgMgr := NewRemoteConfig()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write(tt.body)
			}))
			defer ts.Close()

			got, err := ctgMgr.fetch(ts.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.errStr {
				t.Errorf("fetch() error = %v, wantErrStr %v", err, tt.errStr)
				return
			}

			if !tt.wantErr && !bytes.Equal(got, tt.body) {
				t.Errorf("fetch() = %v, want %v", string(got), tt.body)
			}
		})
	}
}

func TestFetchConfigError(t *testing.T) {
	ctgMgr := NewRemoteConfig()
	_, err := ctgMgr.fetch("invalid://url")
	if err == nil {
		t.Errorf("Expected an error for invalid URL, got nil")
	}
}

func TestFetchConfigBodyReadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1") // This will cause io.ReadAll to fail , sets length to 1 but reads 0 bytes
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctgMgr := NewRemoteConfig()
	_, err := ctgMgr.fetch(ts.URL)
	if err == nil {
		t.Errorf("Expected an error for body read failure, got nil")
	}
}

func TestRetry_Success(t *testing.T) {
	var attempts int32
	fn := func(ctx context.Context) (int, error) {
		atomic.AddInt32(&attempts, 1)
		return 42, nil
	}

	result, err := retry(context.Background(), 3, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Fatalf("unexpected result: %d", result)
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestRetry_FailureThenSuccess(t *testing.T) {
	var attempts int32
	fn := func(ctx context.Context) (int, error) {
		currentAttempts := atomic.AddInt32(&attempts, 1)
		if currentAttempts < 3 {
			return 0, errors.New("temporary failure")
		}
		return 42, nil
	}

	result, err := retry(context.Background(), 5, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Fatalf("unexpected result: %d", result)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestRetry_ContextCancellation(t *testing.T) {
	var attempts int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fn := func(ctx context.Context) (int, error) {
		atomic.AddInt32(&attempts, 1)
		if atomic.LoadInt32(&attempts) == 2 {
			cancel()
		}
		return 0, errors.New("temporary failure")
	}

	_, err := retry(ctx, 5, fn)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected 2 attempts, got: %d", atomic.LoadInt32(&attempts))
	}
}
