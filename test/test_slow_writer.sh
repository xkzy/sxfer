#!/bin/bash
set -e

echo "=== Testing Active Writer Detection in Watch Mode ==="
WATCH_DIR=$(mktemp -d /tmp/sxfer_writer_watch_XXXXXX)
RECV_DIR=$(mktemp -d /tmp/sxfer_writer_recv_XXXXXX)
PIPE=$(mktemp -u /tmp/sxfer_writer_pipe_XXXXXX)
mkfifo "$PIPE"

cleanup() {
    kill $SENDER_PID $RECV_PID 2>/dev/null || true
    rm -rf "$WATCH_DIR" "$RECV_DIR" "$PIPE"
}
trap cleanup EXIT

# Start receiver in continuous loop mode (-q 0)
./sxfer recv -d "$PIPE" -o "$RECV_DIR" -q 0 &
RECV_PID=$!
sleep 0.3

# Start sender in watch mode
./sxfer send -d "$PIPE" -w "$WATCH_DIR" -f 35 &
SENDER_PID=$!
sleep 0.8

# Start a background process writing slowly to a file
TARGET_FILE="$WATCH_DIR/slowly_written.dat"
python3 -c '
import time, os
with open("'"$TARGET_FILE"'", "wb") as f:
    for i in range(5):
        f.write(os.urandom(20000))
        f.flush()
        time.sleep(0.3)
' &
WRITER_PID=$!

echo "Writer started. Waiting for writer to complete..."
wait $WRITER_PID
echo "Writer finished writing 100KB file."

# Wait for sxfer send to detect that writing finished, send, and delete
for i in {1..30}; do
    if [ ! -e "$TARGET_FILE" ]; then break; fi
    sleep 0.2
done

if [ -e "$TARGET_FILE" ]; then
    echo "FAIL: $TARGET_FILE was not processed and deleted after writer finished!"
    exit 1
fi

echo "File processed and deleted from watch directory."

# Verify receiver received full 100KB intact
test -f "$RECV_DIR/slowly_written.dat"
RECV_SIZE=$(stat -c%s "$RECV_DIR/slowly_written.dat")
if [ "$RECV_SIZE" -ne 100000 ]; then
    echo "FAIL: Received file size is $RECV_SIZE, expected 100000!"
    exit 1
fi

echo "=== ACTIVE WRITER DETECTION PASSED! Size: $RECV_SIZE bytes verified ==="
