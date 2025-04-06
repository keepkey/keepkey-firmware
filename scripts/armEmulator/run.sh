#!/bin/sh
set -e

python3 ./scripts/armEmulator/bridge.py &
./bin/kkemu
