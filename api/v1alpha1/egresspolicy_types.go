// Package v1alpha1 contains API Schema definitions for the policy v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=policy.kubenanny.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultAction specifies the fallback action when a hostname cannot be
// extracted or is not in the allowlist.
// +kubebuilder:validation:Enum=allow;deny
type DefaultAction string

const (
	DefaultActionAllow DefaultAction = "allow"
	DefaultActionDeny  DefaultAction = "deny"
)

// EgressPolicySpec defines the desired egress filtering behaviour.
type EgressPolicySpec struct {
	// PodSelector selects the pods to which this policy applies.
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// AllowedHostnames is the list of hostnames that matched pods are
	// permitted to connect to. Supports exact match (e.g. "api.example.com")
	// and wildcard prefix (e.g. "*.example.com") which matches any subdomain.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`
	AllowedHostnames []string `json:"allowedHostnames"`

	// DefaultAction specifies the action for traffic where the hostname
	// cannot be determined (non-HTTP/non-TLS). Defaults to "deny".
	// +kubebuilder:default=deny
	DefaultAction DefaultAction `json:"defaultAction,omitempty"`
}

// EgressPolicyStatus describes the observed state of the policy.
type EgressPolicyStatus struct {
	// Enforced indicates whether the eBPF programs are loaded and active.
	Enforced bool `json:"enforced,omitempty"`

	// MatchedPods is the number of pods on this node matching the selector.
	MatchedPods int32 `json:"matchedPods,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Enforced",type=boolean,JSONPath=`.status.enforced`
// +kubebuilder:printcolumn:name="Pods",type=integer,JSONPath=`.status.matchedPods`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// EgressPolicy is the Schema for the egresspolicies API.
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressPolicySpec   `json:"spec,omitempty"`
	Status EgressPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EgressPolicyList contains a list of EgressPolicy resources.
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressPolicy `json:"items"`
}
