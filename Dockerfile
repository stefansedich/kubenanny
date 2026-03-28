# Stage 1: Build BPF objects and Go binary
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /bin/kubenanny ./cmd/kubenanny

# Stage 2: Run tests (used by `make docker-test`)
FROM builder AS test
RUN go vet ./...
RUN go test ./... -v -count=1

# Stage 3: Minimal runtime image
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /bin/kubenanny /kubenanny

ENTRYPOINT ["/kubenanny"]
