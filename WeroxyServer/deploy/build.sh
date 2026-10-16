#!/bin/sh
set -eu
# Build-time Node/npm only; the executable embeds the generated local Web.
server_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${GO_BIN:-go}
version=${VERSION:-0.4.0}
python3 "$server_dir/../scripts/third_party_notices.py" --check
output=${1:-"$server_dir/../dist/server/weroxy-Server"}
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
command -v "$go_bin" >/dev/null
command -v npm >/dev/null
mkdir -p "$(dirname -- "$output")"
(cd "$server_dir/web" && npm ci --no-audit --no-fund && npm run build)
(cd "$server_dir" && GOTOOLCHAIN=local CGO_ENABLED=0 "$go_bin" build -trimpath -buildvcs=false -ldflags "-X weroxy/server/internal/buildinfo.Version=$version" -o "$output" ./cmd/weroxy-Server)
printf 'Built %s\n' "$output"
