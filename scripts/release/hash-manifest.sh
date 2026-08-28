#!/bin/sh
# Generate the published hash manifest for a directory of release artifacts.
#
# This exists as a script rather than as steps inside release.yml because the
# manifest has to be produced TWICE: once by CI over the unsigned build, and
# again by the key holders over the signed binaries they are about to upload.
# When only CI could generate it, the published full-image hash described the
# unsigned draft -- the binary nobody installs -- while the checklist quietly
# swapped the signed one in underneath it. That is the most likely origin of
# the wrong v7.14.1 hash that ended up pinned in KeepKey Vault.
#
# Usage:
#   scripts/release/hash-manifest.sh <dir> <version> <variant> [suffix]
#   scripts/release/hash-manifest.sh --require-signed <dir> <version> <variant> [suffix]
#   scripts/release/hash-manifest.sh --self-test
#
# Writes HASHES<suffix>.txt into <dir>. With --require-signed it exits non-zero
# unless every application firmware image carries three distinct signer slots
# and three non-zero signatures -- run it that way before publishing.
#
# Application metadata descriptor (include/keepkey/board/memory.h):
#   0x00  4  magic 'KPKY'      0x08  1  sig_index1     0x40  64  signature 1
#   0x04  4  codelen (LE)      0x09  1  sig_index2     0x80  64  signature 2
#                              0x0A  1  sig_index3     0xC0  64  signature 3
#                              0x0B  1  sig_flag
set -eu

sha256() { { command -v sha256sum >/dev/null && sha256sum; } || shasum -a 256; }
digest() { sha256 | awk '{print $1}'; }

# EVERY od CALL PASSES -v. Without it od collapses repeated identical lines to
# a single '*', so 192 zero bytes render as one line of zeros plus '*' -- and
# the '*' survives `tr -d '0'`, which made an entirely unsigned image read as
# signed. That defect is the reason this file's checks are per-region below
# rather than one concatenated blob.
#
# Little-endian uint32 at byte offset $2 of file $1. NR==1 because od closes
# with a trailing offset line that awk would otherwise emit as a second value.
le32() {
  od -v -An -tu1 -j"$2" -N4 "$1" |
    awk 'NR == 1 {print $1 + $2 * 256 + $3 * 65536 + $4 * 16777216}'
}
u8() { od -v -An -tu1 -j"$2" -N1 "$1" | awk 'NR == 1 {print $1}'; }
is_kpky() { [ "$(od -v -An -c -N4 "$1" | tr -d ' \n')" = "KPKY" ]; }

# True if the 64-byte signature slot $2 (0..2) of file $1 is not all zeroes.
sig_present() {
  _off=$((64 + $2 * 64))
  [ -n "$(od -v -An -tx1 -j"$_off" -N64 "$1" | tr -d ' \n' | tr -d '0')" ]
}

# A 3-of-5 quorum: three signer slots, each in the valid range 1..5, all
# distinct, and each of the three 64-byte signature regions independently
# non-zero.
#
# WHAT THIS PROVES, EXACTLY: that the canonical unsigned draft -- zero indices,
# zero signature area -- was not published. Nothing more. A region holding a
# single non-zero byte passes, so this cannot distinguish a real ECDSA
# signature from a placeholder, and it cannot detect a forgery at all.
#
# The five signing public keys are in include/keepkey/board/pubkeys.h, so real
# verification is not blocked on obtaining them -- it needs a host-side
# secp256k1 verifier over sha256 of the image, which nobody has written. Until
# that exists, do not let this check be described as proof the release is
# correctly signed.
has_quorum() {
  _i1=$(u8 "$1" 8); _i2=$(u8 "$1" 9); _i3=$(u8 "$1" 10)
  for _i in "$_i1" "$_i2" "$_i3"; do
    [ "$_i" -ge 1 ] && [ "$_i" -le 5 ] || return 1
  done
  [ "$_i1" -ne "$_i2" ] && [ "$_i1" -ne "$_i3" ] && [ "$_i2" -ne "$_i3" ] || return 1
  sig_present "$1" 0 && sig_present "$1" 1 && sig_present "$1" 2
}
signer_slots() { printf '%s,%s,%s' "$(u8 "$1" 8)" "$(u8 "$1" 9)" "$(u8 "$1" 10)"; }

fail() { echo "self-test: $1"; exit 1; }

# Writes 64 non-zero bytes into signature slot $2 (0..2) of $1.
sign_slot() {
  _o=$((64 + $2 * 64))
  dd if=/dev/zero bs=1 count=64 2>/dev/null | tr '\000' '\052' |
    dd of="$1" bs=1 seek="$_o" conv=notrunc 2>/dev/null
}

self_test() {
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  # 256-byte descriptor + 4 bytes of "code": magic, codelen=4, no signatures.
  printf 'KPKY\004\000\000\000' > "$d/f.bin"
  dd if=/dev/zero bs=1 count=248 >> "$d/f.bin" 2>/dev/null
  printf 'code' >> "$d/f.bin"
  is_kpky "$d/f.bin" || fail "magic not detected"
  [ "$(le32 "$d/f.bin" 4)" = "4" ] || fail "codelen misread"
  has_quorum "$d/f.bin" && fail "unsigned image claimed quorum"

  # THE od REGRESSION. Valid distinct in-range slots, but the whole 192-byte
  # signature area is still zero. Under `od` without -v that area renders as one
  # zero line plus '*', and the '*' survived `tr -d '0'`, so this exact shape --
  # an unsigned binary with its indices filled in -- passed the gate.
  printf '\001\002\004\001' | dd of="$d/f.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
  has_quorum "$d/f.bin" && fail "all-zero signature area passed quorum (od -v)"

  # One signature present is not three. The previous self-test wrote a single
  # byte here and declared the quorum valid, which is why none of this was
  # caught.
  sign_slot "$d/f.bin" 0
  has_quorum "$d/f.bin" && fail "one signature passed a 3-of-5 quorum"
  sign_slot "$d/f.bin" 1
  has_quorum "$d/f.bin" && fail "two signatures passed a 3-of-5 quorum"
  sign_slot "$d/f.bin" 2
  has_quorum "$d/f.bin" || fail "three signed slots failed quorum"

  # Slots outside 1..5 are not signers, however non-zero.
  printf '\001\002\006' | dd of="$d/f.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
  has_quorum "$d/f.bin" && fail "out-of-range signer slot 6 passed quorum"
  printf '\001\002\000' | dd of="$d/f.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
  has_quorum "$d/f.bin" && fail "zero signer slot passed quorum"

  # Repeated slots are not a quorum, however non-zero.
  printf '\001\001\004' | dd of="$d/f.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
  has_quorum "$d/f.bin" && fail "duplicate slots passed quorum"

  # And --require-signed must refuse a directory with no application image
  # rather than reporting success over nothing.
  e=$(mktemp -d)
  if sh "$0" --require-signed "$e" 0.0.0 full "" >/dev/null 2>&1; then
    rm -rf "$e"; fail "--require-signed passed an empty directory"
  fi
  rm -rf "$e"

  echo "self-test: ok"
}

[ "${1:-}" = "--self-test" ] && { self_test; exit 0; }

REQUIRE_SIGNED=0
if [ "${1:-}" = "--require-signed" ]; then REQUIRE_SIGNED=1; shift; fi

DIR=$1; VERSION=$2; VARIANT=$3; SUFFIX=${4:-}
cd "$DIR"

OUT="HASHES${SUFFIX}.txt"
: > "$OUT"

# Signed-ness is read off the artifacts rather than passed in, so the manifest
# cannot claim a state the bytes do not support.
#
# APPS counts application images. Without it "no unsigned image found" and "no
# image found at all" were the same answer, so --require-signed exited 0 on an
# empty directory and announced "Generated from the signed release artifacts" --
# a gate that passes when there is nothing to gate.
# Exactly one application image, and it must be the one this invocation names.
# A directory holding both variants' artifacts -- which is precisely what the
# release job's merge-multiple download produces -- would otherwise hash the
# bitcoin-only image into the full variant's manifest and vice versa.
EXPECTED_APP="firmware.keepkey.v${VERSION}${SUFFIX}.bin"
UNSIGNED=0
APPS=0
for f in *.bin; do
  [ -f "$f" ] || continue
  is_kpky "$f" || continue
  if [ "$f" != "$EXPECTED_APP" ]; then
    echo "ERROR: unexpected application image '$f'; this manifest is for" >&2
    echo "       '${EXPECTED_APP}'. Generate each variant from its own" >&2
    echo "       directory, or the variants cross-contaminate." >&2
    exit 1
  fi
  APPS=$((APPS + 1))
  has_quorum "$f" || UNSIGNED=1
done

if [ "$REQUIRE_SIGNED" -eq 1 ] && [ "$APPS" -eq 0 ]; then
  echo "ERROR: no application image '${EXPECTED_APP}' in $(pwd) —" >&2
  echo "       nothing to publish." >&2
  exit 1
fi

{
  echo "# KeepKey Firmware v${VERSION} (${VARIANT}) — Hash Manifest"
  echo "#"
  if [ "$UNSIGNED" -eq 1 ]; then
    echo "# THESE ARE THE UNSIGNED BUILD ARTIFACTS. Signing rewrites the 256-byte"
    echo "# metadata descriptor, which CHANGES every 'device image' and 'whole file'"
    echo "# hash below. Regenerate this file from the signed binaries before"
    echo "# publishing:"
    echo "#   scripts/release/hash-manifest.sh --require-signed . ${VERSION} ${VARIANT} ${SUFFIX}"
    echo "# Only the 'payload' hash survives signing unchanged."
  else
    echo "# Generated from the signed release artifacts: ${APPS} application"
    echo "# image, carrying three distinct signer slots in 1..5 and three"
    echo "# non-empty signature regions."
    echo "#"
    echo "# That is a STRUCTURAL check with a narrow meaning: it proves the"
    echo "# canonical UNSIGNED DRAFT was not published. It does NOT verify the"
    echo "# signatures, and a region holding one non-zero byte would pass it."
  fi
  echo ""
} >> "$OUT"

for f in *.bin *.elf; do
  [ -f "$f" ] || continue
  WHOLE=$(digest < "$f")

  if ! is_kpky "$f"; then
    # No KPKY descriptor: a bootloader image or a build product. The
    # device-image and payload framings below simply do not apply to it, and
    # applying them is how 'tail -c +257' ended up recommended for
    # bootloader.bin.
    {
      echo "$f  (no KPKY application descriptor)"
      echo "  sha256 (whole file)    $WHOLE"
      echo "    The file as published. This is NOT what Features.firmware_hash"
      echo "    reports, and 'tail -c +257' does not apply to it."
      echo ""
    } >> "$OUT"
    continue
  fi

  CODELEN=$(le32 "$f" 4)
  SIZE=$(wc -c < "$f" | tr -d ' ')

  # head -c stops at EOF without complaining, so a truncated image would be
  # hashed over fewer bytes than its own descriptor claims and published as if
  # it were whole.
  if [ "$SIZE" -lt $((256 + CODELEN)) ]; then
    echo "ERROR: '$f' is ${SIZE} bytes but its descriptor claims 256+${CODELEN}" >&2
    echo "       = $((256 + CODELEN)). Truncated image; refusing to hash it." >&2
    exit 1
  fi

  DEVICE=$(head -c $((256 + CODELEN)) "$f" | digest)
  PAYLOAD=$(tail -c +257 "$f" | digest)

  if has_quorum "$f"; then
    STATE="signed, signer slots $(signer_slots "$f")"
  else
    STATE="UNSIGNED"
  fi

  {
    echo "$f  (application firmware, ${STATE})"
    echo "  sha256 (device image)  $DEVICE"
    echo "    Compare against the firmware hash your device reports"
    echo "    (Features.firmware_hash, shown in KeepKey Vault)."
    echo "    Covers the 256-byte metadata descriptor -- signatures included --"
    echo "    plus codelen (${CODELEN}) bytes of application code."
    echo "    Signing CHANGES this hash."
    echo "  sha256 (whole file)    $WHOLE"
    if [ "$SIZE" -eq $((256 + CODELEN)) ]; then
      echo "    The file as published; identical to the device image hash above."
    else
      echo "    The file as published. It is ${SIZE} bytes against a"
      echo "    256+codelen device image of $((256 + CODELEN)), so the two hashes"
      echo "    DIFFER. Pin the device image hash, not this one."
    fi
    echo "  sha256 (payload)       $PAYLOAD"
    echo "    Compare against your own reproducible build, with"
    echo "    'tail -c +257' applied to BOTH files -- a local build"
    echo "    has no signatures in its 256-byte descriptor."
    echo "    This proves the release binary came from the source."
    echo "    Signing does NOT change this hash, and it is NOT the hash"
    echo "    the device reports."
    echo ""
  } >> "$OUT"
done

cat "$OUT"

if [ "$REQUIRE_SIGNED" -eq 1 ] && [ "$UNSIGNED" -eq 1 ]; then
  echo "ERROR: an application firmware image is missing its 3-of-5 quorum." >&2
  exit 1
fi
