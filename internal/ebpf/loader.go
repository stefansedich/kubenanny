// Package ebpf handles loading, attaching and managing the eBPF programs and maps.
package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I../../bpf" egressFilter ../../bpf/egress_filter.c

// Loader manages the lifecycle of eBPF programs and their attachment to
// network interfaces.
type Loader struct {
	mu      sync.Mutex
	objs    *egressFilterObjects
	links   map[string]link.Link // ifname → TC link
	mapsMgr *MapManager
	logger  *slog.Logger
}

// NewLoader creates a new Loader. Call Load() to load the BPF objects.
func NewLoader(logger *slog.Logger) *Loader {
	return &Loader{
		links:  make(map[string]link.Link),
		logger: logger,
	}
}

// Load loads the compiled eBPF objects into the kernel.
func (l *Loader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	objs := &egressFilterObjects{}
	if err := loadEgressFilterObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			l.logger.Error("verifier log", "log", fmt.Sprintf("%+v", ve))
		}
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	l.objs = objs
	l.mapsMgr = &MapManager{
		PodPolicy:           objs.PodPolicy,
		PolicyHostnames:     objs.PolicyHostnames,
		PolicyDefaultAction: objs.PolicyDefaultAction,
		Conntrack:           objs.Conntrack,
	}
	l.logger.Info("eBPF objects loaded successfully")
	return nil
}

// Maps returns the MapManager for CRUD operations on BPF maps.
func (l *Loader) Maps() *MapManager {
	return l.mapsMgr
}

// EventsMap returns the ringbuf events map for the event reader.
func (l *Loader) EventsMap() *ebpf.Map {
	if l.objs == nil {
		return nil
	}
	return l.objs.Events
}

// AttachTC attaches the egress filter TC program to the given network interface.
func (l *Loader) AttachTC(ifaceName string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.links[ifaceName]; exists {
		return nil // Already attached
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", ifaceName, err)
	}

	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.EgressFilter,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attaching TC to %s: %w", ifaceName, err)
	}

	l.links[ifaceName] = lnk
	l.logger.Info("TC program attached", "interface", ifaceName)
	return nil
}

// DetachTC detaches the TC program from the given interface.
func (l *Loader) DetachTC(ifaceName string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	lnk, exists := l.links[ifaceName]
	if !exists {
		return nil
	}

	if err := lnk.Close(); err != nil {
		return fmt.Errorf("detaching TC from %s: %w", ifaceName, err)
	}

	delete(l.links, ifaceName)
	l.logger.Info("TC program detached", "interface", ifaceName)
	return nil
}

// Close releases all eBPF resources.
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for ifname, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			l.logger.Error("closing TC link", "interface", ifname, "error", err)
		}
	}
	l.links = make(map[string]link.Link)

	if l.objs != nil {
		return l.objs.Close()
	}
	return nil
}

// IsLoaded returns true if BPF objects have been loaded.
func (l *Loader) IsLoaded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.objs != nil
}
