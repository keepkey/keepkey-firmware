#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
cd deps/python-keepkey/tests
KK_TRANSPORT_MAIN=kkemu:11044 KK_TRANSPORT_DEBUG=kkemu:11045 pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
