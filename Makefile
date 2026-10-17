VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
IMAGE   ?= ghcr.io/mrguato/pisentry

.PHONY: all test vet build dist image sim clean

all: vet test build

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)

test:
	go test -race ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o pisentry ./cmd/pisentry

# Static binaries for every supported board.
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64           go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pisentry-linux-arm64 ./cmd/pisentry
	CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOARM=7   go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pisentry-linux-armv7 ./cmd/pisentry
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64           go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pisentry-linux-amd64 ./cmd/pisentry
	cd dist && sha256sum pisentry-* > SHA256SUMS

image:
	docker buildx build --platform linux/arm64,linux/arm/v7,linux/amd64 \
		--build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) --push .

clean:
	rm -rf dist pisentry

# Container-based attack simulation. Builds the binary in the pinned Go image,
# then fires harmless stand-ins for eight detectors inside a python:3-slim
# container and checks all eight fired. Needs only Docker, no root on the host.
# See scripts/sim-container/ and CONTRIBUTING.md ("Proving a detector").
sim:
	docker run --rm -v "$(CURDIR)":/src -w /src golang:1.27-alpine \
		sh -c 'CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o pisentry ./cmd/pisentry'
	scripts/sim-container/sim.sh ./pisentry
