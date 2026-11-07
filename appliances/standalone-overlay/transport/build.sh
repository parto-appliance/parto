#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ARCH=${APPLIANCE_ARCH:-amd64}
case "$ARCH" in amd64|arm64) ;; *) exit 2;; esac
OUTPUT="$HERE/../artifacts/transport-$ARCH"
mkdir -p "$OUTPUT"
docker run --rm --network none \
 --mount "type=bind,source=$HERE,target=/src,readonly" \
 --mount "type=bind,source=$OUTPUT,target=/out" \
 -e "GOARCH=$ARCH" -e GOOS=linux -e CGO_ENABLED=0 -e GOTOOLCHAIN=local \
 -w /src golang@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb \
 go build -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/parto-transport .
