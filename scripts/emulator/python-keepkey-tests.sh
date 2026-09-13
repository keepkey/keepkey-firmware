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

REPORT_BUILD_VARIANT=${KK_TEST_BUILD_VARIANT:-full}
case "$REPORT_BUILD_VARIANT" in
    full|bitcoin-only) ;;
    *)
        echo "FATAL: unsupported KK_TEST_BUILD_VARIANT=$REPORT_BUILD_VARIANT"
        exit 1
        ;;
esac
REPORT_VARIANT_ARG="--build-variant=$REPORT_BUILD_VARIANT"
echo "Expected CI build variant: $REPORT_BUILD_VARIANT"

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

# The tests run from this directory, while keepkeylib lives one level up.
# Make that package root explicit so direct imports work consistently in the
# standalone container (including tests collected before common.py is loaded).
export PYTHONPATH="..${PYTHONPATH:+:$PYTHONPATH}"

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
# Use exact module::method selectors from the report catalog, so unrelated tests
# with similar names cannot satisfy a screenshot expectation.
echo "=== Phase 1: Report-driven screenshot capture ==="
# Detect firmware version from CMakeLists if not set in env.
# The Alpine/BusyBox container needs a portable sed expression here.
if [ -z "$FW_VERSION" ]; then
    # Fail rather than defaulting: a wrong version silently narrows the
    # screenshot catalog and report validation.
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
SCREENSHOT_TESTS=$(python3 ../scripts/generate-test-report.py \
    --screenshot-test-list --fw-version="$FW_VERSION" "$REPORT_VARIANT_ARG")
if [ -z "$SCREENSHOT_TESTS" ]; then
    echo "FATAL: screenshot test list is empty"
    echo "1" > /kkemu/test-reports/python-keepkey/status
    exit 1
fi
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KEEPKEY_SCREENSHOT_TESTS="$SCREENSHOT_TESTS" \
KK_EXPECT_PERSIST_REJECTED=1 \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --tb=short \
  $PYTEST_TIMEOUT_ARGS \
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
    "$REPORT_VARIANT_ARG" \
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
set +e
KK_EXPECT_PERSIST_REJECTED=1 \
KK_EXPECT_ENTROPY_BUDGET=1 \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v $PYTEST_TIMEOUT_ARGS --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
PYTEST_RC=$?

# Merge in the native firmware unit results before validating or rendering.
# The test-reports volume is shared rw with the firmware-unit container, which
# runs first, so its XMLs are already here. Validating against the Python JUnit
# alone made every catalog entry naming a native unit test resolve to "missing",
# which is why no native test could ever be catalogued and all 432 of them were
# invisible to the report.
#
# If the native XMLs are absent this falls back to Python-only, and any native
# catalog entry then fails as "missing" -- i.e. it still fails closed, it does
# not quietly pass.
echo "=== Phase 2: Merge JUnit evidence ==="
MERGED=/kkemu/test-reports/junit-merged.xml
python3 - <<'PY'
import glob, os, xml.etree.ElementTree as ET
files = sorted(glob.glob('/kkemu/test-reports/python-keepkey/junit*.xml'))
native = sorted(glob.glob('/kkemu/test-reports/firmware-unit/*.xml'))
root = ET.Element('testsuites')
for f in files + native:
    try:
        for suite in ET.parse(f).iter('testsuite'):
            root.append(suite)
    except ET.ParseError:
        print("WARN: skipping malformed %s" % f)
ET.ElementTree(root).write('/kkemu/test-reports/junit-merged.xml',
                           xml_declaration=True, encoding='unicode')
print("Merged %d Python + %d native JUnit file(s)" % (len(files), len(native)))
if not native:
    print("WARN: no firmware-unit XMLs found; native catalog entries will "
          "report as missing")
PY
[ -s "$MERGED" ] || MERGED=/kkemu/test-reports/python-keepkey/junit.xml

echo "=== Phase 2: Validate report catalog ==="
python3 ../scripts/generate-test-report.py \
  --junit="$MERGED" \
  "$REPORT_VARIANT_ARG" \
  ${FW_VERSION:+--fw-version=$FW_VERSION} \
  --validate-junit
CATALOG_RC=$?

echo "=== Phase 2: Generate test report ==="
python3 ../scripts/generate-test-report.py \
  --junit="$MERGED" \
  "$REPORT_VARIANT_ARG" \
  ${FW_VERSION:+--fw-version=$FW_VERSION} \
  --screenshots=/kkemu/test-reports/screenshots \
  --output=/kkemu/test-reports/test-report.pdf
REPORT_RC=$?
set -e

if [ "$PYTEST_RC" -eq 0 ] && [ "$CATALOG_RC" -eq 0 ] && [ "$REPORT_RC" -eq 0 ]; then
    echo "0" > /kkemu/test-reports/python-keepkey/status
else
    echo "1" > /kkemu/test-reports/python-keepkey/status
fi
if [ "$PYTEST_RC" -ne 0 ]; then
    echo "pytest failed with exit code $PYTEST_RC"
    exit "$PYTEST_RC"
fi
if [ "$CATALOG_RC" -ne 0 ]; then
    echo "report catalog validation failed with exit code $CATALOG_RC"
    exit "$CATALOG_RC"
fi
if [ "$REPORT_RC" -ne 0 ]; then
    echo "test report generation failed with exit code $REPORT_RC"
    exit "$REPORT_RC"
fi
