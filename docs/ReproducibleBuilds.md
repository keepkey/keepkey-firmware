# Reproducible Builds

KeepKey firmware releases are built deterministically: anyone can rebuild a
release tag from source and confirm, byte for byte, that it matches the binary
we ship. This page explains how to verify that, and why the naive "hash both
files" comparison is guaranteed to fail even for a perfect build.

## One-command verification

```bash
git clone https://github.com/keepkey/keepkey-firmware
cd keepkey-firmware
./scripts/build/verify-repro.sh v7.15.0
```

The script clones the tag into a temporary directory, builds it with the
official Docker image (`kktech/firmware:v15`, the same pinned image used for
releases), downloads the signed release binary from GitHub, and compares the
device-verifiable payload hashes. It prints all four hashes and `PASS`/`FAIL`.

Requirements: `git`, `docker`, `curl`, ~2 GB of disk, and about 15 minutes.

## The 256-byte header, or: why full-file hashes never match

`firmware.keepkey.bin` starts with a 256-byte metadata header
(`tools/firmware/header.s`):

| offset (bytes) | size | contents                     |
|---------------:|-----:|------------------------------|
| 0              | 4    | magic `KPKY`                 |
| 4              | 4    | payload length               |
| 8              | 3    | signature key indexes        |
| 11             | 1    | flags                        |
| 12             | 52   | reserved (zero)              |
| 64             | 192  | three 64-byte signatures     |
| 256            | —    | payload (the actual firmware)|

In a freshly built binary the signature indexes and signature slots are all
**zeros**. The release process signs that exact binary, filling in the key
indexes and the three secp256k1 signatures (3-of-5 against the public keys in
`include/keepkey/board/pubkeys.h`). Nothing after byte 256 changes.

Consequently, for any correctly reproduced build:

- `sha256(built file)` **never** equals `sha256(signed release file)` — the
  header bytes differ by construction;
- `sha256` of everything **after** byte 256 is identical on both sides — this
  payload hash is the reproducibility check, and it is also what the device
  itself can attest to.

## Manual verification

```bash
git clone https://github.com/keepkey/keepkey-firmware
cd keepkey-firmware
git checkout v7.15.0
git submodule update --init --recursive
./scripts/build/docker/device/release.sh

# payload hash of your build:
tail -c +257 bin/firmware.keepkey.bin | sha256sum

# payload hash of the official release:
curl -fsSL -o official.bin \
  https://github.com/keepkey/keepkey-firmware/releases/download/v7.15.0/firmware.keepkey.bin
tail -c +257 official.bin | sha256sum
```

The two payload hashes must be equal. Each release's `HASHES.txt` asset lists
the expected values.

## Cross-checks

- The firmware embeds the git commit it was built from
  (`lib/firmware/scm_revision.h.in`); a device reports it in
  `Features.revision`, so you can confirm which commit produced the binary a
  device is actually running.
- The device also reports `Features.firmware_hash`, computed on-device over
  the installed image, which host software can compare against published
  release hashes.
