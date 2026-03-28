package controller

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1alpha1 "github.com/stefansedich/kubenanny/api/v1alpha1"
	bpf "github.com/stefansedich/kubenanny/internal/ebpf"
)

// EgressPolicyReconciler reconciles EgressPolicy objects and configures eBPF
// maps and TC attachments accordingly.
type EgressPolicyReconciler struct {
	client.Client
	Loader   *bpf.Loader
	Logger   *slog.Logger
	NodeName string
	// policyIDs tracks policy_id → namespaced name to detect hash collisions.
	policyIDs map[uint32]types.NamespacedName
}

// NewEgressPolicyReconciler creates a new reconciler.
func NewEgressPolicyReconciler(c client.Client, loader *bpf.Loader, logger *slog.Logger, nodeName string) *EgressPolicyReconciler {
	return &EgressPolicyReconciler{
		Client:    c,
		Loader:    loader,
		Logger:    logger,
		NodeName:  nodeName,
		policyIDs: make(map[uint32]types.NamespacedName),
	}
}

// SetupWithManager registers the controller with the manager.
func (r *EgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.EgressPolicy{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.podToPolicy)).
		Complete(r)
}

// podToPolicy maps a Pod event to the EgressPolicy objects that select it.
func (r *EgressPolicyReconciler) podToPolicy(ctx context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}

	// Only care about pods on this node.
	if pod.Spec.NodeName != r.NodeName {
		return nil
	}

	var policyList policyv1alpha1.EgressPolicyList
	if err := r.List(ctx, &policyList, client.InNamespace(pod.Namespace)); err != nil {
		r.Logger.Error("listing policies for pod mapping", "error", err)
		return nil
	}

	var requests []reconcile.Request
	for _, policy := range policyList.Items {
		sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			})
		}
	}
	return requests
}

// Reconcile handles an EgressPolicy event.
func (r *EgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.With("policy", req.NamespacedName)

	var policy policyv1alpha1.EgressPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Policy deleted — clean up.
		return ctrl.Result{}, r.handleDelete(req)
	}

	policyID := policyHash(req.NamespacedName)

	// Detect hash collisions — two different policies must not share a policy ID.
	if existing, ok := r.policyIDs[policyID]; ok && existing != req.NamespacedName {
		return ctrl.Result{}, fmt.Errorf("policy ID hash collision: %q and %q both map to %d", existing, req.NamespacedName, policyID)
	}
	r.policyIDs[policyID] = req.NamespacedName

	logger.Info("reconciling", "policyID", policyID)

	// Find matching pods on this node.
	sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("parsing pod selector: %w", err)
	}

	var podList corev1.PodList
	if err := r.List(ctx, &podList,
		client.InNamespace(req.Namespace),
		client.MatchingLabelsSelector{Selector: sel},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing pods: %w", err)
	}

	maps := r.Loader.Maps()
	if maps == nil {
		return ctrl.Result{}, fmt.Errorf("BPF maps not available")
	}

	// Update hostname allowlist.
	if err := maps.UpdatePolicyHostnames(policyID, policy.Spec.AllowedHostnames); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating hostnames: %w", err)
	}

	// Update default action.
	allow := policy.Spec.DefaultAction == policyv1alpha1.DefaultActionAllow
	if err := maps.UpdateDefaultAction(policyID, allow); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating default action: %w", err)
	}

	// Update pod→policy mappings.
	var matchedPods int32
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Spec.NodeName != r.NodeName || pod.Status.PodIP == "" {
			continue
		}

		podIP := net.ParseIP(pod.Status.PodIP)
		if podIP == nil {
			continue
		}

		if err := maps.UpdatePodPolicy(podIP, policyID); err != nil {
			logger.Error("updating pod policy map", "pod", pod.Name, "error", err)
			continue
		}
		matchedPods++
	}

	// Update status only when enforced changes from false to true, to avoid
	// a reconcile storm between DaemonSet instances constantly overwriting
	// each other's matchedPods count. Once enforced=true, the status is
	// considered stable and further updates are skipped.
	if !policy.Status.Enforced {
		policy.Status.Enforced = true
		policy.Status.MatchedPods = matchedPods
		if err := r.Status().Update(ctx, &policy); err != nil {
			logger.Error("updating policy status", "error", err)
		}
	}

	// Attach TC to all veth interfaces so the egress filter program runs.
	r.attachVeths(logger)

	logger.Info("reconciled", "matchedPods", matchedPods)
	return ctrl.Result{}, nil
}

// attachVeths discovers veth interfaces on this node and attaches the TC
// egress filter. AttachTC is idempotent — already-attached interfaces are
// skipped.
func (r *EgressPolicyReconciler) attachVeths(logger *slog.Logger) {
	links, err := netlink.LinkList()
	if err != nil {
		logger.Error("listing network interfaces for TC attachment", "error", err)
		return
	}
	for _, l := range links {
		name := l.Attrs().Name
		if strings.HasPrefix(name, "veth") {
			if err := r.Loader.AttachTC(name); err != nil {
				logger.Error("attaching TC to veth", "interface", name, "error", err)
			}
		}
	}
}

func (r *EgressPolicyReconciler) handleDelete(req ctrl.Request) error {
	policyID := policyHash(req.NamespacedName)
	delete(r.policyIDs, policyID)
	maps := r.Loader.Maps()
	if maps == nil {
		return nil
	}
	r.Logger.Info("cleaning up deleted policy", "policy", req.NamespacedName, "policyID", policyID)
	return maps.DeletePolicy(policyID)
}

// policyHash generates a stable uint32 policy ID from a namespaced name.
func policyHash(nn types.NamespacedName) uint32 {
	h := fnv.New32a()
	h.Write([]byte(nn.Namespace))
	h.Write([]byte("/"))
	h.Write([]byte(nn.Name))
	return h.Sum32()
}
