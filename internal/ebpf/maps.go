package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// MapManager provides typed CRUD operations on the BPF maps.
type MapManager struct {
	PodPolicy           *ebpf.Map
	PolicyHostnames     *ebpf.Map
	PolicyDefaultAction *ebpf.Map
	Conntrack           *ebpf.Map
}

// podPolicyKey matches struct pod_policy_key in maps.h.
type podPolicyKey struct {
	PodIP uint32 // network byte order
}

// podPolicyVal matches struct pod_policy_val in maps.h.
type podPolicyVal struct {
	PolicyID uint32
}

// policyHostnameKey matches struct policy_hostname_key in maps.h.
type policyHostnameKey struct {
	PolicyID     uint32
	Pad          uint32 // padding to match C struct alignment
	HostnameHash uint64
}

// policyHostnameVal matches struct policy_hostname_val in maps.h.
type policyHostnameVal struct {
	Action uint8
}

// policyDefaultKey matches struct policy_default_key in maps.h.
type policyDefaultKey struct {
	PolicyID uint32
}

// policyDefaultVal matches struct policy_default_val in maps.h.
type policyDefaultVal struct {
	Action uint8
}

// ipToU32BE converts an IPv4 net.IP to a uint32 whose memory layout matches
// the BPF program's raw __be32 load from the IP header. NativeEndian ensures
// the stored bytes are identical to the IP address bytes in network order.
func ipToU32BE(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	return binary.NativeEndian.Uint32(ip4), nil
}

// UpdatePodPolicy associates a pod IP with a policy ID.
func (m *MapManager) UpdatePodPolicy(podIP net.IP, policyID uint32) error {
	ipVal, err := ipToU32BE(podIP)
	if err != nil {
		return err
	}
	key := podPolicyKey{PodIP: ipVal}
	val := podPolicyVal{PolicyID: policyID}
	return m.PodPolicy.Update(key, val, ebpf.UpdateAny)
}

// DeletePodPolicy removes a pod IP from the policy map.
func (m *MapManager) DeletePodPolicy(podIP net.IP) error {
	ipVal, err := ipToU32BE(podIP)
	if err != nil {
		return err
	}
	key := podPolicyKey{PodIP: ipVal}
	return m.PodPolicy.Delete(key)
}

// UpdatePolicyHostnames sets the allowed hostnames for a given policy.
// It hashes each hostname and inserts (policy_id, hash) → allow.
func (m *MapManager) UpdatePolicyHostnames(policyID uint32, hostnames []string) error {
	for _, h := range hostnames {
		hash := FNV1aHash([]byte(h))
		key := policyHostnameKey{PolicyID: policyID, HostnameHash: hash}
		val := policyHostnameVal{Action: 1} // allow
		if err := m.PolicyHostnames.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("updating hostname %q: %w", h, err)
		}
	}
	return nil
}

// DeletePolicyHostnames removes hostname entries for a policy.
func (m *MapManager) DeletePolicyHostnames(policyID uint32, hostnames []string) error {
	for _, h := range hostnames {
		hash := FNV1aHash([]byte(h))
		key := policyHostnameKey{PolicyID: policyID, HostnameHash: hash}
		// Ignore "not found" errors — entry may already be gone.
		_ = m.PolicyHostnames.Delete(key)
	}
	return nil
}

// UpdateDefaultAction sets the default action for a policy.
func (m *MapManager) UpdateDefaultAction(policyID uint32, allow bool) error {
	key := policyDefaultKey{PolicyID: policyID}
	action := uint8(0)
	if allow {
		action = 1
	}
	val := policyDefaultVal{Action: action}
	return m.PolicyDefaultAction.Update(key, val, ebpf.UpdateAny)
}

// DeletePolicy removes all map entries associated with a policy ID.
// This is a best-effort cleanup — it iterates the hostname map. For
// conntrack, entries will naturally expire via LRU eviction.
func (m *MapManager) DeletePolicy(policyID uint32) error {
	// Delete default action
	dKey := policyDefaultKey{PolicyID: policyID}
	_ = m.PolicyDefaultAction.Delete(dKey)

	// Iterate and delete matching hostname entries
	var key policyHostnameKey
	var val policyHostnameVal
	iter := m.PolicyHostnames.Iterate()
	var toDelete []policyHostnameKey
	for iter.Next(&key, &val) {
		if key.PolicyID == policyID {
			toDelete = append(toDelete, key)
		}
	}
	for _, k := range toDelete {
		_ = m.PolicyHostnames.Delete(k)
	}

	// Remove pod_policy entries pointing to this policy so the BPF
	// stops filtering traffic for pods that were covered by it.
	var ppKey podPolicyKey
	var ppVal podPolicyVal
	ppIter := m.PodPolicy.Iterate()
	var ppToDelete []podPolicyKey
	for ppIter.Next(&ppKey, &ppVal) {
		if ppVal.PolicyID == policyID {
			ppToDelete = append(ppToDelete, ppKey)
		}
	}
	for _, k := range ppToDelete {
		_ = m.PodPolicy.Delete(k)
	}

	// Flush conntrack so cached allow/deny decisions from the deleted
	// policy do not persist for in-progress connections.
	var ctKey [16]byte
	var ctVal [1]byte
	ctIter := m.Conntrack.Iterate()
	var ctToDelete [][16]byte
	for ctIter.Next(&ctKey, &ctVal) {
		ctToDelete = append(ctToDelete, ctKey)
	}
	for _, k := range ctToDelete {
		_ = m.Conntrack.Delete(k)
	}

	return nil
}
