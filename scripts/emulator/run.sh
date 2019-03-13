#!/bin/sh
set -e

./bin/kkemu&
#FLASK_APP=./scripts/emulator/bridge.py flask run
python ./scripts/emulator/bridge.py
