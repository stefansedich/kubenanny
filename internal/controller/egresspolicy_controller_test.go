package controller

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func TestPolicyHash_Deterministic(t *testing.T) {
	nn := types.NamespacedName{Namespace: "default", Name: "my-policy"}
	h1 := policyHash(nn)
	h2 := policyHash(nn)
	if h1 != h2 {
		t.Fatalf("policyHash not deterministic: %d != %d", h1, h2)
	}
}

func TestPolicyHash_DifferentNamespaces(t *testing.T) {
	a := policyHash(types.NamespacedName{Namespace: "ns-a", Name: "policy"})
	b := policyHash(types.NamespacedName{Namespace: "ns-b", Name: "policy"})
	if a == b {
		t.Fatal("different namespaces should produce different hashes")
	}
}

func TestPolicyHash_DifferentNames(t *testing.T) {
	a := policyHash(types.NamespacedName{Namespace: "default", Name: "alpha"})
	b := policyHash(types.NamespacedName{Namespace: "default", Name: "beta"})
	if a == b {
		t.Fatal("different names should produce different hashes")
	}
}

func TestPolicyHash_NonZero(t *testing.T) {
	h := policyHash(types.NamespacedName{Namespace: "default", Name: "test"})
	if h == 0 {
		t.Fatal("policyHash should not return 0 for non-empty input")
	}
}

func TestPolicyHash_NamespaceNameSeparation(t *testing.T) {
	// "ab/c" vs "a/bc" must differ — the separator "/" prevents ambiguity.
	a := policyHash(types.NamespacedName{Namespace: "ab", Name: "c"})
	b := policyHash(types.NamespacedName{Namespace: "a", Name: "bc"})
	if a == b {
		t.Fatal("namespace/name boundary should be unambiguous (ab/c != a/bc)")
	}
}

func TestPolicyHash_EmptyNamespace(t *testing.T) {
	h := policyHash(types.NamespacedName{Namespace: "", Name: "policy"})
	if h == 0 {
		t.Fatal("policyHash with empty namespace should not return 0")
	}
}

func TestPolicyHash_EmptyName(t *testing.T) {
	h := policyHash(types.NamespacedName{Namespace: "default", Name: ""})
	if h == 0 {
		t.Fatal("policyHash with empty name should not return 0")
	}
}

func TestPolicyHash_LongInput(t *testing.T) {
	// Verify long namespace/name combinations don't panic.
	long := types.NamespacedName{
		Namespace: "very-long-namespace-name-that-exceeds-typical-length",
		Name:      "extremely-long-policy-name-for-testing-purposes-only",
	}
	h := policyHash(long)
	if h == 0 {
		t.Fatal("policyHash should not return 0 for long input")
	}
}

func TestPolicyHash_CommonNames(t *testing.T) {
	// Make sure common policy names in different namespaces produce different IDs.
	names := []types.NamespacedName{
		{Namespace: "default", Name: "deny-all"},
		{Namespace: "production", Name: "deny-all"},
		{Namespace: "staging", Name: "deny-all"},
	}
	seen := make(map[uint32]string)
	for _, nn := range names {
		h := policyHash(nn)
		key := nn.Namespace + "/" + nn.Name
		if prev, ok := seen[h]; ok {
			t.Fatalf("collision: %q and %q hash to %d", prev, key, h)
		}
		seen[h] = key
	}
}
