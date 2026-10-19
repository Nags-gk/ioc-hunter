#!/usr/bin/env bash
# Download Loghub's OpenSSH dataset and verify its hash before use.
set -euo pipefail
DEST=${1:-data}
URL="https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
SHA="296610a35773f58b7c295e5407fc5ccdf48beb3c544fc14a6309addf904a2712"
mkdir -p "$DEST"
curl -sSL --fail -o "$DEST/SSH.tar.gz" "$URL"
echo "$SHA  $DEST/SSH.tar.gz" | sha256sum -c -
tar -xzf "$DEST/SSH.tar.gz" -C "$DEST" SSH.log
echo "$DEST/SSH.log"
