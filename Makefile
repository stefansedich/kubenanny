# ── Configuration ───────────────────────────────────────────────
BINARY       := kubenanny
IMAGE        := kubenanny:latest
CLUSTER_NAME := kubenanny-dev
HELM_RELEASE := kubenanny
HELM_NS      := kubenanny-system
HELM_CHART   := charts/kubenanny

.PHONY: help generate build clean test test/unit test/integration lint dev \
        docker/build docker/test \
        helm/lint \
        k3d/create k3d/delete k3d/load k3d/deploy k3d/undeploy k3d/logs

## ── General ────────────────────────────────────────────────────

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; section=""} \
		/^## ──/ { section=$$0; gsub(/^## /, "", section); gsub(/ ─+$$/, "", section); gsub(/^─+ /, "", section); next } \
		/^[a-zA-Z_\/][a-zA-Z0-9_\/-]+:.*?##/ { \
			if (section != "") { printf "\n\033[1m%s\033[0m\n", section; section="" } \
			gsub(/:.*/, "", $$1); printf "  \033[36m%-20s\033[0m%s\n", $$1, $$2 \
		}' $(MAKEFILE_LIST)
	@echo ""

generate: ## Run go generate (requires BPF toolchain)
	go generate ./...

build: generate ## Build the Linux binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(BINARY) ./cmd/kubenanny

clean: ## Remove build artifacts
	rm -rf bin/

test: test/unit test/integration ## Run all tests (unit + integration)

test/unit: ## Run unit tests (BPF packages will fail on macOS)
	go test ./... -v -count=1

test/integration: k3d/create k3d/deploy ## Run integration tests (sets up cluster + deploys)
	go test -tags integration -v -count=1 -timeout 10m ./test/integration/

lint: ## Run golangci-lint
	golangci-lint run ./...

dev: test/integration ## Full local cycle: cluster + build + deploy + test
	@echo ""
	@echo "Local dev cluster ready. Use 'make k3d/logs' to view logs."
	@echo "Use 'make k3d/delete' to tear down."

## ── Docker ─────────────────────────────────────────────────────

docker/build: ## Build the Docker image (compiles BPF + Go)
	docker build --platform linux/amd64 -t $(IMAGE) .

docker/test: ## Run go vet + go test inside Docker
	docker build --platform linux/amd64 --target test -t $(IMAGE)-test .

## ── Helm ───────────────────────────────────────────────────────

helm/lint: ## Lint the Helm chart
	helm lint $(HELM_CHART)

## ── k3d ────────────────────────────────────────────────────────

k3d/create: ## Create a k3d cluster for local development
	@if k3d cluster list | grep -q $(CLUSTER_NAME); then \
		echo "Cluster $(CLUSTER_NAME) already exists"; \
	else \
		k3d cluster create $(CLUSTER_NAME) \
			--agents 1 \
			--k3s-arg "--disable=traefik@server:0" \
			--k3s-arg "--disable=metrics-server@server:0" \
			--image rancher/k3s:v1.31.4-k3s1 \
			--wait; \
		echo "Cluster $(CLUSTER_NAME) created."; \
	fi
	@kubectl config use-context k3d-$(CLUSTER_NAME)

k3d/delete: ## Delete the k3d cluster
	k3d cluster delete $(CLUSTER_NAME)

k3d/load: docker/build ## Build image and import into k3d
	k3d image import $(IMAGE) --cluster $(CLUSTER_NAME)

k3d/deploy: k3d/load ## Build, load, and deploy via Helm
	helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(HELM_NS) --create-namespace \
		--set image.repository=kubenanny \
		--set image.tag=latest \
		--set image.pullPolicy=IfNotPresent \
		--wait --timeout 120s

k3d/undeploy: ## Remove kubenanny from the cluster
	helm uninstall $(HELM_RELEASE) --namespace $(HELM_NS) --ignore-not-found || true
	kubectl delete crd egresspolicies.policy.kubenanny.io --ignore-not-found

k3d/logs: ## Tail kubenanny logs from the cluster
	kubectl -n $(HELM_NS) logs -l app.kubernetes.io/name=kubenanny -f
