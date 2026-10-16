# Multi-arch build: linux/arm64 (Pi 4/5), linux/arm/v7 (32-bit Pi OS), linux/amd64.
# The Go toolchain cross-compiles natively on the build host, so no QEMU
# emulation is needed for the compile step.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pisentry ./cmd/pisentry

# distroless/static: no shell, no package manager, CA certs for HTTPS webhooks.
# journalctl is NOT in the image on purpose: in Kubernetes pisentry chroots into
# the host and runs the host's own journalctl (logs.journal_chroot=true), so the
# reader always matches the host's journal format.
FROM gcr.io/distroless/static-debian12:latest
LABEL org.opencontainers.image.source="https://github.com/MrGuato/pisentry" \
      org.opencontainers.image.description="Top 10 attack reporting agent for Raspberry Pi and ARM Linux" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/pisentry /usr/local/bin/pisentry
ENTRYPOINT ["/usr/local/bin/pisentry"]
CMD ["run", "-config", "/etc/pisentry/config.json"]
