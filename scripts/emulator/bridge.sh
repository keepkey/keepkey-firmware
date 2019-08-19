#!/bin/sh
set -e

mkdir -p /kkemu/test-reports/bridge-tests
KK_BRIDGE=kkemu:5000 pytest ./scripts/emulator/bridge_test.py --junitxml=/kkemu/test-reports/bridge-tests/junit.xml
echo "$?" > /kkemu/test-reports/bridge-tests/status
