#!/usr/bin/env bash
# Build only native Linux installation packages. Runtime has no Docker dependency.
set -euo pipefail
if [[ $# != 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then echo 'usage: package.sh <semver without v>' >&2; exit 2; fi
version=$1
go_bin=${GO_BIN:-go}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
python3 "$repo_dir/scripts/third_party_notices.py" --check
out_dir=$repo_dir/dist/client/$version
mkdir -p "$out_dir"
if [[ -n $(find "$out_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then echo 'output directory must be empty' >&2;exit 1;fi
work_dir=$(mktemp -d /tmp/weroxy-native-package.XXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo_dir" log -1 --format=%ct)}
export CGO_ENABLED=0 GOTOOLCHAIN=local GOAMD64=v1 GOARM64=v8.0
for arch in amd64 arm64; do
 (cd "$repo_dir/WeroxyClient" && GOOS=linux GOARCH=$arch "$go_bin" build -trimpath -buildvcs=false -ldflags "-s -w -X weroxy/client/internal/buildinfo.Version=$version" -o "$work_dir/weroxy-client-$arch" ./cmd/weroxy-client)
done
cp "$repo_dir/LICENSE" "$work_dir/LICENSE"
cp "$repo_dir/WeroxyClient/THIRD_PARTY_NOTICES" "$work_dir/THIRD_PARTY_NOTICES"
# Explicit isolated build tooling image; never mount installed services or credentials.
tools_image=${WEROXY_PACKAGER_IMAGE:-weroxy-client-packager:20261001}
if ! docker image inspect "$tools_image" >/dev/null 2>&1; then
 docker build -t "$tools_image" -f "$script_dir/packager.Dockerfile" "$script_dir"
fi
docker run --rm --user "$(id -u):$(id -g)" --workdir /work -v "$work_dir:/work" -v "$out_dir:/out" -v "$script_dir:/deploy:ro" "$tools_image" python3 /deploy/package_native.py "$version" "$SOURCE_DATE_EPOCH" "$(id -u)" "$(id -g)"
python3 - "$repo_dir" "$out_dir" "$version" "$go_bin" <<'METADATA'
import sys,pathlib,subprocess,hashlib,json,datetime
repo=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); version=sys.argv[3]
paths=subprocess.check_output(['git','-C',str(repo),'ls-files','--cached','--others','--exclude-standard','WeroxyClient','LICENSE','THIRD_PARTY_NOTICES'],text=True).splitlines()
rows=[]
for name in sorted(set(paths)):
 p=repo/name
 if p.is_file():rows.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+name+'\n')
source=''.join(rows);(out/'SOURCE_SHA256SUMS').write_text(source)
build={'version':version,'baseline_commit':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),
'includes_uncommitted_changes':bool(subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True)),
'go_version':subprocess.check_output([sys.argv[4],'version'],text=True).strip(),'built_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
'source_manifest_sha256':hashlib.sha256(source.encode()).hexdigest(),'architectures':['linux/amd64','linux/arm64'],
'cpu_baseline':{'amd64':'v1','arm64':'v8.0'},'remote_deployed':False}
(out/'BUILD.json').write_text(json.dumps(build,indent=2)+'\n')
with (out/'SHA256SUMS').open('a') as f:
 for name in ['BUILD.json','SOURCE_SHA256SUMS']:f.write(hashlib.sha256((out/name).read_bytes()).hexdigest()+'  '+name+'\n')
METADATA
echo "Built native packages: $out_dir"
