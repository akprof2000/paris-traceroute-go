#!/bin/sh
# Builds paris-traceroute for Linux and Windows (amd64, arm64) and packs
# release archives into ./dist: tar.gz for Linux, zip for Windows.
# Usage: ./build.sh [version]     e.g. ./build.sh v1.0.0
set -e
cd "$(dirname "$0")"
VERSION=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
rm -rf dist
mkdir -p dist
for t in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
	os=${t%/*}
	arch=${t#*/}
	name="paris-traceroute_${VERSION}_${os}_${arch}"
	stage="dist/$name"
	mkdir -p "$stage"
	bin=paris-traceroute
	[ "$os" = windows ] && bin=paris-traceroute.exe
	GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$VERSION" -o "$stage/$bin" ./cmd/paris-traceroute
	cp README.md LICENSE "$stage/"
	if [ "$os" = windows ]; then
		(cd dist && zip -qr "$name.zip" "$name")
	else
		tar -C dist -czf "dist/$name.tar.gz" "$name"
	fi
	rm -rf "$stage"
	echo "packed $name"
done
(cd dist && sha256sum *.tar.gz *.zip > checksums.txt)
