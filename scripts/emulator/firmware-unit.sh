#!/bin/sh
#
# The container's exit status IS the gate: CI runs this through
#   docker compose up --exit-code-from firmware-unit
# and uses that code directly (see .github/workflows/ci.yml, FW_RC).
#
# This script used to end with `cp`, so the exit status was the COPY's, not the
# test run's. A failing `make xunit` wrote its real code into the status file
# below -- which nothing reads -- and the container still exited 0, so the suite
# could not fail this job. Capture the status, always extract the reports (the
# evidence matters most when tests fail), then exit with the status.

mkdir -p /kkemu/test-reports/firmware-unit

make xunit
RC=$?

echo "$RC" > /kkemu/test-reports/firmware-unit/status

# Best-effort: a missing XML must not mask the test result below.
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit 2>/dev/null || \
  echo "WARN: no firmware-unit XML to copy"

exit "$RC"
