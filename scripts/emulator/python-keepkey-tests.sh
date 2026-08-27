#!/bin/sh
set -e

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

if [ -z "$FW_VERSION" ]; then
  FW_VERSION=$(sed -n '/^project/,/)/p' /kkemu/CMakeLists.txt | \
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$FW_VERSION" ]; then
  echo "FATAL: firmware version could not be determined"
  exit 1
fi
export FW_VERSION

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
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml

python3 ../scripts/generate-test-report.py \
  --screenshot-audit=/kkemu/test-reports/screenshots \
  --audit-junit=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  --fw-version="$FW_VERSION"

echo "=== Full Python integration suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml

echo "0" > /kkemu/test-reports/python-keepkey/status
