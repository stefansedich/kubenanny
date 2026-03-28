// Package server provides HTTP health and metrics endpoints.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	bpf "github.com/stefansedich/kubenanny/internal/ebpf"
)

// HealthServer serves liveness, readiness, and metrics endpoints.
type HealthServer struct {
	loader *bpf.Loader
	logger *slog.Logger
	srv    *http.Server
}

// NewHealthServer creates a health/metrics server on the given address.
func NewHealthServer(addr string, loader *bpf.Loader, logger *slog.Logger) *HealthServer {
	mux := http.NewServeMux()
	hs := &HealthServer{
		loader: loader,
		logger: logger,
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
		},
	}

	mux.HandleFunc("/healthz", hs.handleHealthz)
	mux.HandleFunc("/readyz", hs.handleReadyz)
	mux.Handle("/metrics", promhttp.Handler())

	return hs
}

// Start begins serving in the background. Blocks until context is done.
func (hs *HealthServer) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := hs.srv.Shutdown(shutdownCtx); err != nil {
			hs.logger.Error("health server shutdown error", "error", err)
		}
	}()

	hs.logger.Info("health server starting", "addr", hs.srv.Addr)
	if err := hs.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("health server: %w", err)
	}
	return nil
}

func (hs *HealthServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (hs *HealthServer) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if hs.loader.IsLoaded() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not ready: BPF programs not loaded"))
}
