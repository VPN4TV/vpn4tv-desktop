#!/bin/bash
# VPN4TV: build the sing-box daemon from our core into the layout
# electron-builder expects.
#
#   scripts/build-daemon.sh                # host platform → bin/sing-box-daemon
#   scripts/build-daemon.sh windows amd64  # → bin/windows/x64/sing-box-daemon.exe
#
# Set VPN4TV_GO to a Go >= 1.24.7 that is NOT go1.27rc1 (see VPN4TV.md).
set -e
cd "$(dirname "$0")/.."

CORE=${VPN4TV_CORE:-../sing-box-xhttp}
GO=${VPN4TV_GO:-go}
OS=${1:-$(uname -s | tr '[:upper:]' '[:lower:]')}
ARCH=${2:-$(uname -m)}

case "$ARCH" in
  x86_64 | amd64) ARCH=amd64; ELECTRON_ARCH=x64 ;;
  arm64 | aarch64) ARCH=arm64; ELECTRON_ARCH=arm64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  windows) OUTPUT="$PWD/bin/windows/$ELECTRON_ARCH/sing-box-daemon.exe" ;;
  linux)   OUTPUT="$PWD/bin/sing-box-daemon" ;;
  darwin)  OUTPUT="$PWD/bin/sing-box-daemon" ;;  # local development only
  *) echo "unsupported os: $OS" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$OUTPUT")"
echo "==> building the daemon for $OS/$ARCH with $($GO version)"
(cd "$CORE" && "$GO" run ./cmd/internal/build_boxdd -target "$OS/$ARCH" -output "$OUTPUT")
echo "==> $OUTPUT"
ls -la "$OUTPUT"
