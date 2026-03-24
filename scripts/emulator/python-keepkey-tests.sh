#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
cd deps/python-keepkey/tests

# Phase 1: Targeted screenshot capture (fast — key address display tests only)
echo "=== Screenshot capture (targeted tests) ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -k "test_getaddress or test_get_address or test_wipedevice or test_bip85 or test_solana_get or test_tron_get or test_ton_get" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  --timeout=120 2>&1 || true

# Phase 2: Full test suite (no screenshots — normal speed)
echo "=== Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
