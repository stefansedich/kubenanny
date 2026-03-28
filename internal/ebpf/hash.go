package ebpf

// FNV-1a 64-bit hash — must match the BPF-side implementation in sni_parser.h.
const (
	fnvOffsetBasis uint64 = 14695981039346656037
	fnvPrime       uint64 = 1099511628211
)

// maxHostnameLen must match MAX_HOSTNAME_LEN in bpf/sni_parser.h.
const maxHostnameLen = 64

// FNV1aHash computes the FNV-1a 64-bit hash of data,
// capped at maxHostnameLen bytes to match the BPF-side implementation.
func FNV1aHash(data []byte) uint64 {
	hash := fnvOffsetBasis
	n := len(data)
	if n > maxHostnameLen {
		n = maxHostnameLen
	}
	for i := 0; i < n; i++ {
		hash ^= uint64(data[i])
		hash *= fnvPrime
	}
	return hash
}
