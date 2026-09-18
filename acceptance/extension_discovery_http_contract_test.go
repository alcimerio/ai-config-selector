package acceptance_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Exercise the same handler and final counters consumed by native cleanup.
// A refusal response alone must never make prohibited traffic acceptable.
func TestDiscoveryCodexHTTPFinalClassification(t *testing.T) {
	for _, tc := range []struct {
		name            string
		hook            bool
		method, target  string
		forbidden       int64
		metadataFailure bool
	}{
		{"optional-absent", true, "", "", 0, false},
		{"optional-present", true, "GET", "/plugins/featured?platform=codex", 0, false},
		{"plugin-session", false, "GET", "/plugins/featured?platform=codex", 1, false},
		{"inference", true, "POST", "/responses", 1, false},
		{"unknown-post", true, "POST", "/unknown", 1, false},
		{"model-catalog", true, "GET", "/models", 0, true},
		{"unknown-get", true, "GET", "/unknown", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &discoveryCodexHTTPHandler{hook: tc.hook}
			if tc.hook {
				h.featured = &discoveryCodexFeaturedMetadata{}
			}
			var wantTotal int64
			if tc.method != "" {
				wantTotal = 1
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(tc.method, "http://fixture"+tc.target, http.NoBody))
				if tc.name == "optional-present" && (w.Code != 501 || w.Body.Len() != 0 || w.Header().Get("Connection") != "close") {
					t.Fatal("optional metadata must retain empty closing refusal")
				}
			}
			total, forbidden, overflow := h.summary()
			if total != wantTotal || forbidden != tc.forbidden || overflow != 0 {
				t.Fatalf("final counters total=%d forbidden=%d overflow=%d", total, forbidden, overflow)
			}
			if h.featured != nil {
				_, failure := h.featured.summary()
				if (failure != "") != tc.metadataFailure {
					t.Fatalf("metadata failure=%q", failure)
				}
			}
		})
	}
}

func TestDiscoveryCodexHTTPOverflowClosesAndRemainsFailed(t *testing.T) {
	h := &discoveryCodexHTTPHandler{hook: true, featured: &discoveryCodexFeaturedMetadata{}}
	closed := 0
	h.onOverflow = func() { closed++ }
	for i := 0; i < 9; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://fixture/plugins/featured?platform=codex", http.NoBody))
		if i < 8 && closed != 0 {
			t.Fatal("listener closed before total cap")
		}
	}
	total, forbidden, overflow := h.summary()
	if closed != 1 || total != 9 || forbidden != 0 || overflow != 1 {
		t.Fatalf("closed=%d total=%d forbidden=%d overflow=%d", closed, total, forbidden, overflow)
	}
	_, failure := h.featured.summary()
	if failure != "metadata-duplicate" {
		t.Fatalf("duplicate failure lost: %q", failure)
	}
}
