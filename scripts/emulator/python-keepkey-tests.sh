#!/bin/sh
set -e

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots

# Wait for emulator
echo "=== Waiting for emulator ==="
for i in $(seq 1 20); do
  if echo -n "PINGPING" | nc -u -w1 kkemu 11044 2>/dev/null | grep -q PONG; then
    echo "Emulator ready (attempt $i)"
    break
  fi
  echo "  attempt $i/20..."
  sleep 2
done

cd deps/python-keepkey/tests

# Diagnostic: verify SCREENSHOT flag reaches Python
echo "=== Pre-flight diagnostic ==="
KEEPKEY_SCREENSHOT=1 python3 -c "
import os, sys
sys.path.insert(0, '..')
print('KEEPKEY_SCREENSHOT env:', os.environ.get('KEEPKEY_SCREENSHOT', 'NOT SET'))
from keepkeylib.client import SCREENSHOT
print('SCREENSHOT global:', SCREENSHOT)
# Check if _capture_oled has debug logging
import inspect
from keepkeylib.client import DebugLinkMixin
src = inspect.getsource(DebugLinkMixin._capture_oled)
has_debug = '[SCREENSHOT]' in src
print('_capture_oled has debug logging:', has_debug)
print('_capture_oled first 200 chars:', repr(src[:200]))
" 2>&1
echo "=== End diagnostic ==="

# Phase 1: Screenshot captures driven by report SECTIONS (single source of truth)
#
# generate-test-report.py --screenshot-filter reads SECTIONS and emits a pytest -k
# expression for every test with non-empty screenshot expectations. Adding screenshots
# to a test in SECTIONS automatically includes it here — no manual filter maintenance.
echo "=== Phase 1: Report-driven screenshot capture ==="
# Detect firmware version from CMakeLists if not set in env.
# NOTE: grep -oE (POSIX ERE), NOT -oP — this runs in the Alpine/busybox
# python-keepkey container where grep has no -P (PCRE). With -P grep errored
# and the version silently fell back to 7.14.0, so every 7.15.0 section
# (Hive, EVM clear-signing) was excluded from screenshot capture.
if [ -z "$FW_VERSION" ]; then
    FW_VERSION=$(sed -n '/^project/,/)/p' /kkemu/CMakeLists.txt | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -z "$FW_VERSION" ] && FW_VERSION="7.14.0"
    echo "Detected FW_VERSION=$FW_VERSION from CMakeLists.txt"
fi
export FW_VERSION
SCREENSHOT_FILTER=$(python3 ../scripts/generate-test-report.py --screenshot-filter --fw-version=$FW_VERSION 2>/dev/null)
if [ -z "$SCREENSHOT_FILTER" ]; then
    echo "WARNING: --screenshot-filter returned empty, falling back to full suite"
    SCREENSHOT_FILTER="test_"
fi
echo "Filter: $SCREENSHOT_FILTER"
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --tb=short \
  -k "$SCREENSHOT_FILTER" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  -s 2>&1 || true
# pytest exit code is NOT the gate — screenshot count below is.
# Tests for features not yet merged (gated by requires_firmware/requires_message)
# may fail or skip here; the real check is: did screenshots get captured?

# Gate: fail fast if screenshots broken
echo "=== Screenshot results ==="
find /kkemu/test-reports/screenshots -name '*.png' -ls 2>/dev/null || echo "NO SCREENSHOTS"
SCREENSHOT_COUNT=$(find /kkemu/test-reports/screenshots -name '*.png' 2>/dev/null | wc -l)
echo "Total PNGs: $SCREENSHOT_COUNT"
if [ "$SCREENSHOT_COUNT" -eq 0 ]; then
    echo "FATAL: KEEPKEY_SCREENSHOT=1 but 0 PNGs captured. Screenshot pipeline is broken."
    echo "1" > /kkemu/test-reports/python-keepkey/status
    exit 1
fi

# Phase 2: Full test suite — SECTIONS is the source of truth.
# pytest may exit non-zero (some tests fail before gating kicks in),
# so we capture the JUnit XML regardless, then validate against SECTIONS.
# Tests that skip via requires_message/requires_firmware are OK.
# Tests that fail or are missing from JUnit = CI failure.
echo "=== Phase 2: Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
PYTEST_RC=$?

echo "=== Phase 2: Generate test report ==="
python3 ../scripts/generate-test-report.py \
  --junit=/kkemu/test-reports/python-keepkey/junit.xml \
  ${FW_VERSION:+--fw-version=$FW_VERSION} || true

echo "$PYTEST_RC" > /kkemu/test-reports/python-keepkey/status
if [ "$PYTEST_RC" -ne 0 ]; then
    echo "pytest failed with exit code $PYTEST_RC"
    exit "$PYTEST_RC"
fi
