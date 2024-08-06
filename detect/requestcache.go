package detect

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type RequestCache struct {
	cache map[string]*http.Response
	mu    sync.Mutex
}

func NewRequestCache() *RequestCache {
	// TODO store just the status code?
	return &RequestCache{
		cache: make(map[string]*http.Response),
	}
}

func (rc *RequestCache) Get(url string, headers map[string]string) (*http.Response, bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	key := generateRequestKey(url, headers)
	result, exists := rc.cache[key]
	return result, exists
}

func (rc *RequestCache) Set(url string, headers map[string]string, resp *http.Response) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	key := generateRequestKey(url, headers)
	rc.cache[key] = resp
}

// Helper function to generate a unique key for each request based on its URL and headers.
func generateRequestKey(url string, headers map[string]string) string {
	// Combine URL and sorted headers to create a unique key.
	var headerStrings []string
	for k, v := range headers {
		headerStrings = append(headerStrings, k+":"+v)
	}
	sort.Strings(headerStrings) // Sort to ensure order is consistent
	key := url + "|" + strings.Join(headerStrings, "|")

	// Compute the FNV hash of the key.
	h := fnv.New64a()
	h.Write([]byte(key))
	return fmt.Sprintf("%x", h.Sum64())

}
