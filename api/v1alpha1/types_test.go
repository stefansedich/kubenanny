package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestEgressPolicy_DeepCopy(t *testing.T) {
	original := &EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: EgressPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			AllowedHostnames: []string{"api.github.com", "httpbin.org"},
			DefaultAction:    DefaultActionDeny,
		},
		Status: EgressPolicyStatus{
			Enforced:    true,
			MatchedPods: 3,
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	copied := original.DeepCopy()

	// Verify the copy is a distinct object.
	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}

	// Verify spec fields match.
	if len(copied.Spec.AllowedHostnames) != len(original.Spec.AllowedHostnames) {
		t.Fatalf("AllowedHostnames length mismatch: %d != %d",
			len(copied.Spec.AllowedHostnames), len(original.Spec.AllowedHostnames))
	}
	for i, h := range original.Spec.AllowedHostnames {
		if copied.Spec.AllowedHostnames[i] != h {
			t.Errorf("AllowedHostnames[%d] = %q, want %q", i, copied.Spec.AllowedHostnames[i], h)
		}
	}

	// Verify mutation independence — modifying the copy must not affect the original.
	copied.Spec.AllowedHostnames[0] = "mutated.example.com"
	if original.Spec.AllowedHostnames[0] == "mutated.example.com" {
		t.Fatal("modifying copy's AllowedHostnames changed original (shallow copy)")
	}

	// Same for labels.
	copied.Spec.PodSelector.MatchLabels["app"] = "changed"
	if original.Spec.PodSelector.MatchLabels["app"] == "changed" {
		t.Fatal("modifying copy's MatchLabels changed original (shallow copy)")
	}

	// Same for conditions.
	copied.Status.Conditions[0].Type = "Changed"
	if original.Status.Conditions[0].Type == "Changed" {
		t.Fatal("modifying copy's Conditions changed original (shallow copy)")
	}
}

func TestEgressPolicy_DeepCopyNil(t *testing.T) {
	var p *EgressPolicy
	if p.DeepCopy() != nil {
		t.Fatal("DeepCopy of nil should return nil")
	}
}

func TestEgressPolicyList_DeepCopy(t *testing.T) {
	original := &EgressPolicyList{
		Items: []EgressPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "a"},
				Spec: EgressPolicySpec{
					AllowedHostnames: []string{"example.com"},
					DefaultAction:    DefaultActionAllow,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "b"},
				Spec: EgressPolicySpec{
					AllowedHostnames: []string{"other.com"},
					DefaultAction:    DefaultActionDeny,
				},
			},
		},
	}

	copied := original.DeepCopy()

	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}
	if len(copied.Items) != 2 {
		t.Fatalf("Items length = %d, want 2", len(copied.Items))
	}

	// Mutation independence.
	copied.Items[0].Name = "mutated"
	if original.Items[0].Name == "mutated" {
		t.Fatal("modifying copy's Items changed original")
	}
}

func TestEgressPolicyList_DeepCopyNil(t *testing.T) {
	var l *EgressPolicyList
	if l.DeepCopy() != nil {
		t.Fatal("DeepCopy of nil should return nil")
	}
}

func TestEgressPolicySpec_DeepCopy(t *testing.T) {
	original := &EgressPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"tier": "frontend"},
		},
		AllowedHostnames: []string{"a.com", "b.com"},
		DefaultAction:    DefaultActionDeny,
	}

	copied := original.DeepCopy()
	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}

	copied.AllowedHostnames = append(copied.AllowedHostnames, "c.com")
	if len(original.AllowedHostnames) != 2 {
		t.Fatal("modifying copy affected original slice")
	}
}

func TestEgressPolicySpec_DeepCopyNil(t *testing.T) {
	var s *EgressPolicySpec
	if s.DeepCopy() != nil {
		t.Fatal("DeepCopy of nil should return nil")
	}
}

func TestEgressPolicyStatus_DeepCopy(t *testing.T) {
	original := &EgressPolicyStatus{
		Enforced:    true,
		MatchedPods: 5,
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionTrue},
		},
	}

	copied := original.DeepCopy()
	copied.Conditions = append(copied.Conditions, metav1.Condition{Type: "New"})
	if len(original.Conditions) != 1 {
		t.Fatal("modifying copy's Conditions affected original")
	}
}

func TestEgressPolicyStatus_DeepCopyNil(t *testing.T) {
	var s *EgressPolicyStatus
	if s.DeepCopy() != nil {
		t.Fatal("DeepCopy of nil should return nil")
	}
}

func TestEgressPolicy_DeepCopyObject(t *testing.T) {
	p := &EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
	}

	obj := p.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	if _, ok := obj.(runtime.Object); !ok {
		t.Fatal("DeepCopyObject should return a runtime.Object")
	}

	if _, ok := obj.(*EgressPolicy); !ok {
		t.Fatal("DeepCopyObject should return *EgressPolicy")
	}
}

func TestEgressPolicyList_DeepCopyObject(t *testing.T) {
	l := &EgressPolicyList{
		Items: []EgressPolicy{{ObjectMeta: metav1.ObjectMeta{Name: "x"}}},
	}

	obj := l.DeepCopyObject()
	if _, ok := obj.(*EgressPolicyList); !ok {
		t.Fatal("DeepCopyObject should return *EgressPolicyList")
	}
}

func TestDefaultActionConstants(t *testing.T) {
	if DefaultActionAllow != "allow" {
		t.Errorf("DefaultActionAllow = %q, want %q", DefaultActionAllow, "allow")
	}
	if DefaultActionDeny != "deny" {
		t.Errorf("DefaultActionDeny = %q, want %q", DefaultActionDeny, "deny")
	}
}

func TestGroupVersionRegistration(t *testing.T) {
	if GroupVersion.Group != "policy.kubenanny.io" {
		t.Errorf("Group = %q, want %q", GroupVersion.Group, "policy.kubenanny.io")
	}
	if GroupVersion.Version != "v1alpha1" {
		t.Errorf("Version = %q, want %q", GroupVersion.Version, "v1alpha1")
	}
}
