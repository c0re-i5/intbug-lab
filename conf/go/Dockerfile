# Pinned golang base; stdlib-only build means no network/module fetch.
# syntax requires BuildKit-free classic builder is fine.
ARG GO_IMAGE
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY server.go .
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
RUN go build -o /lab-h2-go server.go
# Run in the same pinned image (keeps everything one digest).
WORKDIR /
COPY index.html /srv/index.html
EXPOSE 443
ENTRYPOINT ["/lab-h2-go"]
