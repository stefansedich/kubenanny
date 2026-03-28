#!/usr/bin/env bash
# hack/update-codegen.sh — Regenerate deepcopy and CRD manifests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running controller-gen for deepcopy..."
go run sigs.k8s.io/controller-tools/cmd/controller-gen \
    object paths="./api/..."

echo "==> Running controller-gen for CRD manifests..."
go run sigs.k8s.io/controller-tools/cmd/controller-gen \
    crd paths="./api/..." \
    output:crd:artifacts:config=deploy/crds

echo "==> Running bpf2go..."
go generate ./internal/ebpf/...

echo "==> Done."
