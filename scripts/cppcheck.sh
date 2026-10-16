#!/bin/sh
# Shared local/CI static-analysis invocation. Run from the repository root.
set -eu
if [ "$#" -ne 1 ]; then
  echo 'usage: sh scripts/cppcheck.sh OUTPUT_FILE' >&2
  exit 2
fi
version=$(cat "$(dirname "$0")/cppcheck-version")
installed=$(dpkg-query -W -f='${Version}' cppcheck)
if [ "$installed" != "$version" ]; then
  echo "cppcheck package mismatch: expected $version, got $installed" >&2
  exit 1
fi
expected="Cppcheck ${version%%-*}"
actual=$(cppcheck --version)
if [ "$actual" != "$expected" ]; then
  echo "cppcheck executable mismatch: expected $expected, got $actual" >&2
  exit 1
fi
mkdir -p .cppcheck-build
exec cppcheck \
  -j "$(getconf _NPROCESSORS_ONLN)" \
  --cppcheck-build-dir=.cppcheck-build \
  --enable=warning,style,performance,portability \
  --std=c11 --platform=unspecified --inconclusive --force --inline-suppr \
  --suppressions-list=.cppcheck-suppressions \
  -I include -I deps/crypto/trezor-firmware/crypto -I deps/device-protocol \
  -DSTM32F2=1 -DUSE_ETHEREUM=1 -DUSE_KECCAK=1 -DUSE_NANO=1 \
  -DPB_FIELD_16BIT=1 -DEMULATOR=1 \
  '--template=::warning file={file},line={line},col={column}::{severity}: {message} [{id}]' \
  --output-file="$1" --error-exitcode=1 \
  lib/ include/keepkey/ tools/
