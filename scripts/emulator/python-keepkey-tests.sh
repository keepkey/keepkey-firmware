#!/bin/sh
set -e

# The product under test is declared by the workflow matrix, never inferred
# from the device, so a regressed full build cannot select the smaller
# bitcoin-only contract.
case "$KK_FIRMWARE_VARIANT" in
  full|bitcoin-only) ;;
  *) echo "FATAL: KK_FIRMWARE_VARIANT must be full or bitcoin-only (got '$KK_FIRMWARE_VARIANT')"
     exit 1 ;;
esac

# ERC-7730 conformance evidence: the official registry is fetched by CI at a
# pinned commit into the build context, and firmware-unit publishes the
# firmware-backed program validator. On the full product
# KK_REQUIRE_ERC7730_EVIDENCE=1 makes a missing registry or validator a test
# FAILURE instead of a skip. Bitcoin-only firmware has no ERC-7730 engine.
if [ "$KK_FIRMWARE_VARIANT" = full ]; then
  export KK_REQUIRE_ERC7730_EVIDENCE=1
  export ERC7730_FIRMWARE_VALIDATOR=/kkemu-emulator-bin/erc7730-validate
  export ERC7730_REGISTRY=/kkemu/build-inputs/erc7730-registry
  if [ ! -d "$ERC7730_REGISTRY/registry" ]; then
    echo "FATAL: pinned ERC-7730 registry missing at $ERC7730_REGISTRY"
    exit 1
  fi
else
  export KK_REQUIRE_ERC7730_EVIDENCE=0
fi

mkdir -p /kkemu/test-reports/python-keepkey
# This volume can survive retries. Stale frames would make the new report look
# more complete than the exact run really was, so every capture starts empty.
rm -rf /kkemu/test-reports/screenshots
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
# Every suite below runs even if an earlier one fails, so each JUnit file is
# still produced; the script's exit status reports any failure.
RC=0

if [ -z "$FW_VERSION" ]; then
  FW_VERSION=$(sed -n '/^project/,/)/p' /kkemu/CMakeLists.txt | \
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$FW_VERSION" ]; then
  echo "FATAL: firmware version could not be determined"
  exit 1
fi
export FW_VERSION

# Rehearsal runs (repo variable KK_CI_REHEARSAL=1) skip the ~8 min OLED
# capture: they prove each merge is green, not release evidence.
if [ "${KK_CI_REHEARSAL:-}" = 1 ]; then
  echo "=== REHEARSAL: OLED capture skipped, no release evidence ==="
else
  echo "=== Report-required OLED capture ==="
  SCREENSHOT_TESTS=$(python3 ../scripts/generate-test-report.py \
    --screenshot-test-list --fw-version="$FW_VERSION")
  if [ -z "$SCREENSHOT_TESTS" ]; then
    echo "FATAL: screenshot test list is empty"
    exit 1
  fi
  KEEPKEY_SCREENSHOT=1 \
  SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
  KEEPKEY_SCREENSHOT_TESTS="$SCREENSHOT_TESTS" \
  KK_TRANSPORT_MAIN=kkemu:11044 \
  KK_TRANSPORT_DEBUG=kkemu:11045 \
  pytest -v --tb=short \
    --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml || RC=1

  python3 ../scripts/generate-test-report.py \
    --screenshot-audit=/kkemu/test-reports/screenshots \
    --audit-junit=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
    --fw-version="$FW_VERSION" || RC=1
fi

echo "=== Full Python integration suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v . /kkemu/unittests/host/test_p02_transport.py \
  /kkemu/unittests/host/test_p03_recovery.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit.xml || RC=1

KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --tb=short \
  test_msg_ethereum_clearsign_additive.py \
  test_msg_session_trust_lifetime.py \
  test_msg_ripple_sign_tx.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-stack06-contracts.xml || RC=1

echo "=== Stack 07 signing contract regressions ==="
PYTHONPATH=/kkemu/deps/python-keepkey:/kkemu/deps/python-keepkey/tests \
KK_STACK07_FIRMWARE_VARIANT="$KK_FIRMWARE_VARIANT" \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v /kkemu/scripts/emulator/test_stack07_regressions.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-stack07.xml || RC=1

echo "=== Combined authenticator slot boundary ==="
PYTHONPATH=/kkemu/deps/python-keepkey:/kkemu/deps/python-keepkey/tests \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v /kkemu/scripts/emulator/test_stack09_integration.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-stack09-integration.xml || RC=1

echo "=== Stack 10 EVM disclosure regressions ==="
PYTHONPATH=/kkemu/deps/python-keepkey:/kkemu/deps/python-keepkey/tests \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v /kkemu/scripts/emulator/test_stack10_regressions.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-stack10.xml || RC=1

echo "=== Stack 12 Hive validation and consent regressions ==="
PYTHONPATH=/kkemu/deps/python-keepkey:/kkemu/deps/python-keepkey/tests \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v /kkemu/scripts/emulator/test_stack12_regressions.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-stack12.xml || RC=1

echo "=== Stack 13 entropy contract regressions ==="
KK_FORCE_UDP=1 \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v /kkemu/scripts/tests/test_block13_entropy.py \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-stack13.xml || RC=1

echo "$RC" > /kkemu/test-reports/python-keepkey/status
exit "$RC"
