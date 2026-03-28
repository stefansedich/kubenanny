// Package netns resolves pod IPs to their host-side veth interface names.
package netns

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// Resolver finds the host-side veth interface for a given pod IP.
type Resolver struct{}

// NewResolver returns a new Resolver.
func NewResolver() *Resolver {
	return &Resolver{}
}

// FindVethByPodIP returns the host-side veth interface name for the given pod IP.
// It walks all veth interfaces looking for the peer that has the specified IP on
// the other end of the veth pair.
//
// For more robust resolution, the controller can alternatively attach TC to all
// veth interfaces and use source-IP matching in BPF.
func (r *Resolver) FindVethByPodIP(podIP net.IP) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("listing links: %w", err)
	}

	for _, l := range links {
		if l.Type() != "veth" {
			continue
		}
		// Check /sys/class/net/<name>/ifindex to match peer
		name := l.Attrs().Name
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.IP.Equal(podIP) {
				return name, nil
			}
		}
	}

	return "", fmt.Errorf("no veth found for pod IP %s", podIP)
}

// ListVethInterfaces returns all veth interface names on the host.
// Useful for the "attach to all veths" strategy.
func (r *Resolver) ListVethInterfaces() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("reading /sys/class/net: %w", err)
	}

	var veths []string
	for _, e := range entries {
		// veth type is 1 (same as ethernet), so check the device symlink
		// for the "virtual" path component.
		linkPath := filepath.Join("/sys/class/net", e.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}
		if strings.Contains(target, "virtual") && strings.HasPrefix(e.Name(), "veth") {
			veths = append(veths, e.Name())
		}
	}

	return veths, nil
}
