#!/bin/sh

make xunit
mkdir -p /kkemu/test-reports/firmware-unit
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit
