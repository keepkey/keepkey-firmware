#!/bin/sh
set -e

./bin/kkemu&

cd deps/python-keepkey/tests

set +e
pytest --junitxml=../../../bin/junit.xml
STATUS="$?"
set -e

killall kkemu

exit $STATUS
