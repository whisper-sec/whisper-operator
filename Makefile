IMG ?= ghcr.io/whisper-sec/whisper-operator:0.1.0
CONTROLLER_GEN = go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.3

.PHONY: all build test vet generate manifests docker-build helm-lint

all: generate manifests vet test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/manager ./cmd

test:
	go test ./...

vet:
	go vet ./...

generate:
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...

manifests:
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=charts/whisper-operator/crds

docker-build:
	docker build -t $(IMG) .

helm-lint:
	helm lint charts/whisper-operator
