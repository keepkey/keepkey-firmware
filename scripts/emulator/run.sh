#!/bin/sh
set -e

./bin/kkemu&
python ./scripts/emulator/bridge.py&

