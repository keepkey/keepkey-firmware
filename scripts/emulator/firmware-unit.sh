#!/bin/sh

mkdir -p /kkemu/test-reports/firmware-unit
make xunit
echo "$?" > /kkemu/test-reports/firmware-unit/status
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit
