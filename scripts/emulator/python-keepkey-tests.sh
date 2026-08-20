#!/bin/sh
set -e

# Bound every test individually.
#
# A protocol/UI mismatch deadlocks: the firmware blocks waiting for a ButtonAck
# the test never sends (this release added confirmation screens the pinned suite
# does not acknowledge), and the test blocks reading a response that never comes.
# Without a per-test bound that is a 30-minute JOB timeout with no JUnit XML, so
# Phase 2 never completes and every file after the stall is unmeasured -- the
# absence of a result is indistinguishable from a pass.
#
# method=signal rather than thread: thread kills the process, so one deadlock
# still costs the rest of the run. signal raises inside the blocked test, which
# then FAILS BY NAME and the suite continues. Measured on the known-deadlocking
# THORChain file: "1 failed, 5 passed in 20.29s" instead of hanging forever.
#
# 60s is roughly 30x the slowest healthy file in this suite (multisig, ~2s).
# See #466.
PYTEST_TIMEOUT_ARGS="--timeout=60 --timeout-method=signal"

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
# Detect firmware version from CMakeLists if not set in env
if [ -z "$FW_VERSION" ]; then
    # grep -oP is a GNU extension. This container's grep is BusyBox, which has
    # no -P, so the old command ALWAYS failed and `|| echo "7.14.0"` silently
    # supplied a wrong version. Everything downstream keys off this: SECTIONS
    # entries are filtered by ver_ge(fw_version, min_fw), so on the 7.14.2
    # release branch every test gated to 7.14.1 or later was excluded from the
    # screenshot filter AND from report validation. That is why the suites this
    # release changed captured no screens.
    #
    # Use sed only, and FAIL rather than defaulting: a wrong version here is
    # invisible and silently narrows what CI checks.
    FW_VERSION=$(sed -n 's/^[[:space:]]*VERSION[[:space:]]\{1,\}\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\).*/\1/p' /kkemu/CMakeLists.txt | head -1)
    if [ -z "$FW_VERSION" ]; then
        echo "FATAL: could not read VERSION from /kkemu/CMakeLists.txt."
        echo "Refusing to guess -- a wrong FW_VERSION silently narrows the"
        echo "screenshot filter and the SECTIONS validation."
        echo "1" > /kkemu/test-reports/python-keepkey/status
        exit 1
    fi
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
  $PYTEST_TIMEOUT_ARGS \
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

# A total count > 0 cannot distinguish "captured everything" from "captured
# something". On the 7.14.2 rc30 artifact this gate passed with 345 PNGs while
# EVERY suite the release changed captured zero -- the rendering evidence for a
# release about what reaches the screen did not exist, and nothing said so.
# Audit per test: any SECTIONS entry that DECLARED screens must have captured
# some. Skipped tests are excluded; a version-gated test cannot draw.
echo "=== Screenshot audit (per-test) ==="
python3 ../scripts/generate-test-report.py \
    --screenshot-audit /kkemu/test-reports/screenshots \
    --audit-junit /kkemu/test-reports/python-keepkey/junit-screenshots.xml \
    --fw-version=$FW_VERSION || {
    echo "FATAL: tests declared screens they did not capture (see list above)."
    echo "1" > /kkemu/test-reports/python-keepkey/status
    exit 1
}

# Phase 2: Full test suite — SECTIONS is the source of truth.
# pytest may exit non-zero (some tests fail before gating kicks in),
# so we capture the JUnit XML regardless, then validate against SECTIONS.
# Tests that skip via requires_message/requires_firmware are OK.
# Tests that fail or are missing from JUnit = CI failure.
echo "=== Phase 2: Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v $PYTEST_TIMEOUT_ARGS --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
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
