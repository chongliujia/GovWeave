#!/bin/sh
# Build on a trusted build machine, then transfer the archive to the target.
set -eu
cd "$(dirname "$0")/.."
package_os=$(go env GOOS)
package_arch=$(go env GOARCH)
case "$package_os" in linux|darwin) ;; *) echo "Supported targets: Linux and macOS" >&2; exit 1 ;; esac
package_name="govweave-0.2.0-dev-${package_os}-${package_arch}"
package_tmp=$(mktemp -d)
trap 'rm -rf "$package_tmp"' EXIT HUP INT TERM
mkdir -p "$package_tmp/$package_name" dist
CGO_ENABLED=0 GOPROXY=off go build -trimpath -o "$package_tmp/$package_name/govweave" ./cmd/govweave
cp README.md README.zh-CN.md agent.md LICENSE THIRD_PARTY_NOTICES "$package_tmp/$package_name/"
cp -R examples docs schemas api "$package_tmp/$package_name/"
tar -czf "dist/$package_name.tar.gz" -C "$package_tmp" "$package_name"
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "$package_name.tar.gz" > "$package_name.tar.gz.sha256")
else
  (cd dist && shasum -a 256 "$package_name.tar.gz" > "$package_name.tar.gz.sha256")
fi
echo "Created dist/$package_name.tar.gz and checksum (not a signed release)."
