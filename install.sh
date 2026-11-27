#!/bin/sh
# Installs the latest keysec release into $KEYSEC_INSTALL_DIR (default ~/.local/bin).
set -eu

repo="sakethsripada/keysec"
dir="${KEYSEC_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
case "$os" in
  darwin | linux) ;;
  *) echo "unsupported OS: $os (on Windows, download a release zip)" >&2; exit 1 ;;
esac

tag=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
[ -n "$tag" ] || { echo "could not find the latest release" >&2; exit 1; }
archive="keysec_${tag#v}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"

cd "$tmp"
grep " $archive\$" checksums.txt > expected
if command -v sha256sum >/dev/null; then sha256sum -c expected >/dev/null; else shasum -a 256 -c expected >/dev/null; fi
tar -xzf "$archive" keysec

mkdir -p "$dir"
mv keysec "$dir/keysec"
echo "installed keysec $tag to $dir/keysec"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "add $dir to your PATH to use it" ;;
esac
echo "next: keysec init"
