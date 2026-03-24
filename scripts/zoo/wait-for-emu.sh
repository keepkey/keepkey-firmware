#!/bin/sh
# Wait for KeepKey emulator to respond on UDP 11044
# Usage: ./wait-for-emu.sh [host] [port] [timeout_seconds]

HOST="${1:-127.0.0.1}"
PORT="${2:-11044}"
TIMEOUT="${3:-30}"

echo "Waiting for emulator at $HOST:$PORT (timeout ${TIMEOUT}s)..."

i=0
while [ "$i" -lt "$TIMEOUT" ]; do
  # Send PINGPING, expect PONGPONG back
  RESP=$(echo -n "PINGPING" | nc -u -w1 "$HOST" "$PORT" 2>/dev/null | head -c8)
  if [ "$RESP" = "PONGPONG" ]; then
    echo "Emulator ready."
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done

echo "ERROR: Emulator not responding after ${TIMEOUT}s"
exit 1
