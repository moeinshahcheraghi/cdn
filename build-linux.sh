#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

command -v go >/dev/null 2>&1 || {
  echo "Go 1.25 or newer is required."
  exit 1
}

[[ -f go.mod ]] || {
  echo "Put this script beside go.mod."
  exit 1
}

go version
mkdir -p bin

for arch in amd64 arm64; do
  for app in server client; do
    output="bin/tunnel-${app}-linux-${arch}"
    echo "Building ${output} ..."

    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build \
      -mod=readonly \
      -trimpath \
      -ldflags="-s -w" \
      -o "$output" \
      "./cmd/$app"
  done
done

echo "Build completed:"
ls -lh bin/tunnel-*-linux-amd64 bin/tunnel-*-linux-arm64
