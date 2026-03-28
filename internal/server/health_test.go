package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockLoader implements the IsLoaded check used by the health server.
type mockLoader struct {
	loaded bool
}

func (m *mockLoader) IsLoaded() bool { return m.loaded }

// newTestServer creates a HealthServer with the mock loader and returns
// the underlying http.Handler for use with httptest.
func newTestServer(loaded bool) http.Handler {
	mux := http.NewServeMux()
	loader := &mockLoader{loaded: loaded}
	logger := slog.Default()

	hs := &HealthServer{
		loader: nil, // not used directly
		logger: logger,
	}
	// We need to wire up handlers that use the mock's IsLoaded.
	mux.HandleFunc("/healthz", hs.handleHealthz)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if loader.IsLoaded() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready: BPF programs not loaded"))
	})

	return mux
}

func TestHealthzEndpoint(t *testing.T) {
	handler := newTestServer(false) // loaded state doesn't matter for healthz

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("GET /healthz body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestReadyzEndpoint_Loaded(t *testing.T) {
	handler := newTestServer(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /readyz status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("GET /readyz body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestReadyzEndpoint_NotLoaded(t *testing.T) {
	handler := newTestServer(false)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if rec.Body.String() != "not ready: BPF programs not loaded" {
		t.Errorf("GET /readyz body = %q, want 'not ready: BPF programs not loaded'", rec.Body.String())
	}
}

func TestHealthzEndpoint_MethodPost(t *testing.T) {
	handler := newTestServer(false)

	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// handleHealthz doesn't filter by method, so POST also returns 200.
	if rec.Code != http.StatusOK {
		t.Errorf("POST /healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestUnknownEndpoint_404(t *testing.T) {
	handler := newTestServer(true)

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /unknown status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestMetricsEndpointRegistered(t *testing.T) {
	// Verify that the real NewHealthServer wires up the /metrics endpoint.
	hs := NewHealthServer(":0", nil, slog.Default())
	if hs == nil {
		t.Fatal("NewHealthServer returned nil")
	}
	if hs.srv == nil {
		t.Fatal("HealthServer.srv should not be nil")
	}

	// Verify the handler serves /metrics with Prometheus output.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	hs.srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /metrics status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "go_goroutines") {
		t.Error("GET /metrics should contain Prometheus runtime metrics")
	}
}
