#!/bin/sh
set -e

mkdir -p /kkemu/test-reports/python-keepkey

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

echo "=== Full Python integration suite ==="
set +e
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
PYTEST_RC=$?
set -e
echo "$PYTEST_RC" > /kkemu/test-reports/python-keepkey/status
exit "$PYTEST_RC"
