package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"github.com/cilium/ebpf/rlimit"
	policyv1alpha1 "github.com/stefansedich/kubenanny/api/v1alpha1"
	"github.com/stefansedich/kubenanny/internal/controller"

	bpf "github.com/stefansedich/kubenanny/internal/ebpf"
	"github.com/stefansedich/kubenanny/internal/metrics"
	"github.com/stefansedich/kubenanny/internal/server"
)

// version is set via -ldflags at build time.
var version = "dev"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
}

// runConfig holds the CLI-configurable options for the daemon.
type runConfig struct {
	healthAddr string
	probeAddr  string
	logLevel   string
	nodeName   string
}

func newRootCmd() *cobra.Command {
	cfg := &runConfig{}

	root := &cobra.Command{
		Use:   "kubenanny",
		Short: "eBPF-based egress hostname filter for Kubernetes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			level := parseLogLevel(cfg.logLevel)
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
			slog.SetDefault(logger)
			ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			return run(ctx, logger, cfg)
		},
		SilenceUsage: true,
	}

	root.Flags().StringVar(&cfg.healthAddr, "health-addr", "127.0.0.1:9090", "Address for the health/metrics HTTP server")
	root.Flags().StringVar(&cfg.probeAddr, "probe-addr", ":8081", "Address for the controller-manager health probes")
	root.Flags().StringVar(&cfg.logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	root.Flags().StringVar(&cfg.nodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node name (defaults to $NODE_NAME)")

	root.AddCommand(newVersionCmd())

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, cfg *runConfig) error {
	// ── Remove memlock rlimit for BPF map creation ────────────────
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// ── Load eBPF programs ─────────────────────────────────────────
	loader := bpf.NewLoader(logger)
	if err := loader.Load(); err != nil {
		return fmt.Errorf("loading eBPF: %w", err)
	}
	defer loader.Close()

	// ── Start event reader ─────────────────────────────────────────
	evtReader, err := bpf.NewEventReader(loader, func(evt bpf.DenyEvent) {
		logger.Info("egress denied",
			"src_ip", evt.SrcIP,
			"dst_ip", evt.DstIP,
			"dst_port", evt.DstPort,
			"hostname_hash", evt.HostnameHash,
			"policy_id", evt.PolicyID,
		)
		metrics.EgressDeniedTotal.WithLabelValues(
			fmt.Sprintf("%d", evt.PolicyID),
		).Inc()
	}, logger)
	if err != nil {
		return fmt.Errorf("creating event reader: %w", err)
	}
	go evtReader.Run(ctx)

	// ── Start health/metrics server ────────────────────────────────
	healthSrv := server.NewHealthServer(cfg.healthAddr, loader, logger)
	go func() {
		if err := healthSrv.Start(ctx); err != nil {
			logger.Error("health server error", "error", err)
		}
	}()

	// ── Start controller manager ───────────────────────────────────
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         false,
	})
	if err != nil {
		return fmt.Errorf("creating controller manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("adding healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("adding readyz check: %w", err)
	}

	reconciler := controller.NewEgressPolicyReconciler(mgr.GetClient(), loader, logger, cfg.nodeName)
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setting up controller: %w", err)
	}

	logger.Info("starting controller manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("controller manager exited: %w", err)
	}

	return nil
}
