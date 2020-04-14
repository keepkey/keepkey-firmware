#!/bin/sh
set -e

python3 ./scripts/emulator/bridge.py &
./bin/kkemu
