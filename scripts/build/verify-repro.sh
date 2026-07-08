#!/usr/bin/env bash
set -euo pipefail

# verify-repro.sh — one-command reproducible-build verification.
#
# Builds the given release tag from source in a clean temporary clone using the
# official Docker build, then compares the device-verifiable payload hash
# (sha256 of everything after the 256-byte KPKY metadata header) against the
# official signed release binary.
#
# A fresh build has zeroed signature-index bytes and signature slots in its
# 256-byte header; the release-signing step fills them in and changes nothing
# else. Full-file hashes therefore NEVER match between a build and a signed
# release — only the payload comparison below is meaningful. See
# docs/ReproducibleBuilds.md.
#
# Usage:
#   scripts/build/verify-repro.sh v7.15.0
#   scripts/build/verify-repro.sh v7.15.0 --local path/to/firmware.keepkey.bin
#
# --local compares against a signed binary you already have (e.g. before the
# GitHub release assets are published).
#
# Requirements: git, docker, curl (unless --local), ~2 GB disk, ~15 minutes.

TAG="${1:-}"
if [ -z "$TAG" ]; then
  echo "usage: $0 <tag> [--local <signed firmware.keepkey.bin>]" >&2
  exit 2
fi
shift

LOCAL_BIN=""
if [ $# -gt 0 ]; then
  if [ "$1" != "--local" ]; then
    echo "error: unrecognized argument '$1'" >&2
    echo "usage: $0 <tag> [--local <signed firmware.keepkey.bin>]" >&2
    exit 2
  fi
  if [ -z "${2:-}" ] || [ ! -f "$2" ]; then
    echo "error: --local requires a path to an existing signed binary" >&2
    exit 2
  fi
  LOCAL_BIN="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
  shift 2
  if [ $# -gt 0 ]; then
    echo "error: unrecognized trailing argument '$1'" >&2
    exit 2
  fi
fi

REPO_URL="${KEEPKEY_REPO:-https://github.com/keepkey/keepkey-firmware}"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

check_magic() {
  if [ "$(head -c 4 "$1")" != "KPKY" ]; then
    echo "error: $1 does not start with KPKY magic — not a firmware image?" >&2
    exit 1
  fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-verify-repro.XXXXXX")"
echo "work dir: $WORK"

echo "==> cloning $REPO_URL @ $TAG"
git clone --quiet "$REPO_URL" "$WORK/keepkey-firmware"
cd "$WORK/keepkey-firmware"
git checkout --quiet "$TAG"
git submodule update --init --recursive --quiet

echo "==> building via scripts/build/docker/device/release.sh (log: $WORK/build.log)"
if ! ./scripts/build/docker/device/release.sh >"$WORK/build.log" 2>&1; then
  echo "error: build failed — see $WORK/build.log" >&2
  exit 1
fi

BUILT_BIN="$WORK/keepkey-firmware/bin/firmware.keepkey.bin"
if [ ! -f "$BUILT_BIN" ]; then
  echo "error: build produced no bin/firmware.keepkey.bin" >&2
  exit 1
fi

if [ -n "$LOCAL_BIN" ]; then
  OFFICIAL_BIN="$LOCAL_BIN"
else
  OFFICIAL_BIN="$WORK/official.firmware.keepkey.bin"
  ASSET_URL="$REPO_URL/releases/download/$TAG/firmware.keepkey.bin"
  echo "==> downloading official release binary: $ASSET_URL"
  if ! curl -fsSL -o "$OFFICIAL_BIN" "$ASSET_URL"; then
    echo "error: could not download the release asset (not published yet?)" >&2
    echo "hint: compare against a local signed binary: $0 $TAG --local <file>" >&2
    exit 1
  fi
fi

check_magic "$BUILT_BIN"
check_magic "$OFFICIAL_BIN"

payload_hash() {
  tail -c +257 "$1" >"$WORK/.payload.tmp"
  sha256 "$WORK/.payload.tmp"
}

BUILT_FULL="$(sha256 "$BUILT_BIN")"
BUILT_PAYLOAD="$(payload_hash "$BUILT_BIN")"
OFFICIAL_FULL="$(sha256 "$OFFICIAL_BIN")"
OFFICIAL_PAYLOAD="$(payload_hash "$OFFICIAL_BIN")"

echo
echo "built    full file : $BUILT_FULL"
echo "built    payload   : $BUILT_PAYLOAD"
echo "official full file : $OFFICIAL_FULL"
echo "official payload   : $OFFICIAL_PAYLOAD"
echo

if [ "$BUILT_PAYLOAD" = "$OFFICIAL_PAYLOAD" ]; then
  echo "PASS: payload hashes match — $TAG is reproducible from source."
  rm -rf "$WORK"
else
  echo "FAIL: payload hashes differ." >&2
  echo "build tree kept for inspection: $WORK" >&2
  exit 1
fi
