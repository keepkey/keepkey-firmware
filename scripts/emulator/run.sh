#!/bin/sh
set -e

./bin/kkemu&
FLASK_APP=./scripts/emulator/bridge.py flask run &

