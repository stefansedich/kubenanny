package ebpf

import (
	"testing"
)

func TestFNV1aHash_Deterministic(t *testing.T) {
	input := []byte("api.github.com")
	h1 := FNV1aHash(input)
	h2 := FNV1aHash(input)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %d != %d", h1, h2)
	}
}

func TestFNV1aHash_EmptyInput(t *testing.T) {
	got := FNV1aHash([]byte{})
	if got != fnvOffsetBasis {
		t.Fatalf("empty input should return offset basis %d, got %d", fnvOffsetBasis, got)
	}
}

func TestFNV1aHash_NilInput(t *testing.T) {
	got := FNV1aHash(nil)
	if got != fnvOffsetBasis {
		t.Fatalf("nil input should return offset basis %d, got %d", fnvOffsetBasis, got)
	}
}

func TestFNV1aHash_DistinctInputs(t *testing.T) {
	inputs := []string{
		"api.github.com",
		"evil.example.com",
		"httpbin.org",
		"google.com",
		"a.b.c.d.e.f.g",
	}

	hashes := make(map[uint64]string)
	for _, s := range inputs {
		h := FNV1aHash([]byte(s))
		if prev, ok := hashes[h]; ok {
			t.Fatalf("collision between %q and %q: both hash to %d", prev, s, h)
		}
		hashes[h] = s
	}
}

func TestFNV1aHash_NonEmptyDiffersFromBasis(t *testing.T) {
	h := FNV1aHash([]byte("x"))
	if h == fnvOffsetBasis {
		t.Fatal("single-byte input must differ from offset basis")
	}
}

func TestFNV1aHash_KnownValues(t *testing.T) {
	// Pre-computed FNV-1a 64-bit reference values.
	// These serve as regression tests to detect accidental algorithm changes.
	tests := []struct {
		input string
		want  uint64
	}{
		// FNV-1a("") = offset basis
		{"", 14695981039346656037},
		// FNV-1a 64-bit for "a": 0xaf63dc4c8601ec8c
		{"a", 0xaf63dc4c8601ec8c},
	}
	for _, tt := range tests {
		got := FNV1aHash([]byte(tt.input))
		if got != tt.want {
			t.Errorf("FNV1aHash(%q) = %#x, want %#x", tt.input, got, tt.want)
		}
	}
}

func TestFNV1aHash_CaseSensitive(t *testing.T) {
	h1 := FNV1aHash([]byte("Example.COM"))
	h2 := FNV1aHash([]byte("example.com"))
	if h1 == h2 {
		t.Fatal("FNV1aHash should be case-sensitive (lowercasing is caller responsibility)")
	}
}

func TestFNV1aHash_TruncatesAtMaxLen(t *testing.T) {
	// Inputs that share the first 64 bytes but differ after should hash identically.
	base := "abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345" // exactly 64 bytes
	a := base + "EXTRA"
	b := base + "DIFFERENT"
	ha := FNV1aHash([]byte(a))
	hb := FNV1aHash([]byte(b))
	if ha != hb {
		t.Fatalf("inputs differing only after 64 bytes should hash equal, got %#x != %#x", ha, hb)
	}
	// Also verify it matches the base-only hash.
	hBase := FNV1aHash([]byte(base))
	if ha != hBase {
		t.Fatalf("long input hash %#x should equal 64-byte input hash %#x", ha, hBase)
	}
}

func TestFNV1aHash_ExactMaxLen(t *testing.T) {
	// 64-byte input should use all bytes (differ from 63-byte prefix).
	full := []byte("abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345") // 64
	prefix := full[:63]
	hFull := FNV1aHash(full)
	hPrefix := FNV1aHash(prefix)
	if hFull == hPrefix {
		t.Fatal("64-byte and 63-byte prefix should hash differently")
	}
}

func TestFNV1aHash_SingleByte(t *testing.T) {
	// Verify all single-byte inputs produce unique hashes (no trivial collisions).
	seen := make(map[uint64]byte)
	for i := 0; i < 256; i++ {
		h := FNV1aHash([]byte{byte(i)})
		if prev, ok := seen[h]; ok {
			t.Fatalf("collision: byte %d and byte %d both hash to %#x", prev, i, h)
		}
		seen[h] = byte(i)
	}
}

func BenchmarkFNV1aHash(b *testing.B) {
	data := []byte("api.github.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FNV1aHash(data)
	}
}

// TestFNV1aHash_WildcardSuffixConsistency verifies that the Go-side hash
// of "*.example.com" equals what BPF's check_wildcard produces: FNV-1a
// of '*' then '.example.com'. This is the core invariant for wildcard matching.
func TestFNV1aHash_WildcardSuffixConsistency(t *testing.T) {
	tests := []struct {
		hostname string // the full hostname extracted from packet
		wildcard string // the wildcard pattern stored by the user
	}{
		{"api.example.com", "*.example.com"},
		{"foo.bar.example.com", "*.bar.example.com"},
		{"foo.bar.example.com", "*.example.com"},
		{"sub.domain.co.uk", "*.domain.co.uk"},
		{"sub.domain.co.uk", "*.co.uk"},
		{"a.b", "*.b"},
	}

	for _, tt := range tests {
		// What Go stores in the BPF map for the wildcard pattern.
		goHash := FNV1aHash([]byte(tt.wildcard))

		// Simulate what BPF does: find the matching '.' in hostname,
		// then hash '*' + suffix.
		bpfHash := simulateBPFWildcardHash(tt.hostname, tt.wildcard)
		if bpfHash == 0 {
			t.Fatalf("failed to find suffix for hostname=%q wildcard=%q", tt.hostname, tt.wildcard)
		}

		if goHash != bpfHash {
			t.Errorf("wildcard hash mismatch: Go FNV1aHash(%q) = %#x, BPF simulation = %#x",
				tt.wildcard, goHash, bpfHash)
		}
	}
}

// simulateBPFWildcardHash mimics the BPF check_wildcard logic: for a given
// hostname, find the suffix that matches the wildcard pattern, then compute
// FNV-1a('*' + suffix_with_dot).
func simulateBPFWildcardHash(hostname, wildcard string) uint64 {
	// wildcard is "*.suffix" — extract the suffix after '*'
	if len(wildcard) < 2 || wildcard[0] != '*' {
		return 0
	}
	targetSuffix := wildcard[1:] // e.g. ".example.com"

	// Walk the hostname finding dots, just like BPF does.
	h := hostname
	for {
		dotIdx := -1
		for i := 0; i < len(h); i++ {
			if h[i] == '.' {
				dotIdx = i
				break
			}
		}
		if dotIdx < 0 {
			return 0
		}
		suffix := h[dotIdx:] // e.g. ".example.com"
		if suffix == targetSuffix {
			// Compute FNV-1a of '*' + suffix, capped at maxHostnameLen
			return FNV1aHash([]byte("*" + suffix))
		}
		h = h[dotIdx+1:]
	}
}

// TestFNV1aHash_WildcardDistinctFromExact ensures wildcard and exact hashes
// don't collide for the same domain.
func TestFNV1aHash_WildcardDistinctFromExact(t *testing.T) {
	exact := FNV1aHash([]byte("example.com"))
	wildcard := FNV1aHash([]byte("*.example.com"))
	if exact == wildcard {
		t.Fatal("exact and wildcard hash should differ")
	}
}

// TestFNV1aHash_WildcardDifferentLevels ensures different wildcard depths
// produce distinct hashes.
func TestFNV1aHash_WildcardDifferentLevels(t *testing.T) {
	h1 := FNV1aHash([]byte("*.example.com"))
	h2 := FNV1aHash([]byte("*.staging.example.com"))
	h3 := FNV1aHash([]byte("*.com"))
	if h1 == h2 || h1 == h3 || h2 == h3 {
		t.Fatalf("wildcard hashes at different levels should differ: %#x, %#x, %#x", h1, h2, h3)
	}
}
