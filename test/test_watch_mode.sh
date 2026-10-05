#!/bin/bash
set -e

echo "=========================================================="
echo "=== TESTING WATCH DIRECTORY SPOOL & DELETE MODE ==="
echo "=========================================================="

WATCH_DIR=$(mktemp -u /tmp/sxfer_watch_spool_XXXXXX) # non-existent initially!
RECV_DIR=$(mktemp -d /tmp/sxfer_watch_recv_XXXXXX)
PIPE=$(mktemp -u /tmp/sxfer_watch_pipe_XXXXXX)
mkfifo "$PIPE"

cleanup() {
    kill $SENDER_PID $RECV_PID 2>/dev/null || true
    rm -rf "$WATCH_DIR" "$RECV_DIR" "$PIPE"
}
trap cleanup EXIT

echo "1. Starting receiver on $PIPE..."
./sxfer recv -d "$PIPE" -o "$RECV_DIR" -m cobs -q 0 &
RECV_PID=$!
sleep 0.3

echo "2. Starting sender in watch mode on non-existent directory $WATCH_DIR..."
./sxfer send -d "$PIPE" -w "$WATCH_DIR" -m cobs -f 35 -z 6 &
SENDER_PID=$!
sleep 0.8

# Verify watch directory was created automatically
if [ ! -d "$WATCH_DIR" ]; then
    echo "FAIL: Watch directory $WATCH_DIR was not created automatically!"
    exit 1
fi
echo "   -> Watch directory auto-creation: OK"

echo "3. Dropping File 1 (small text) into $WATCH_DIR..."
echo "First test file content transferred via watch mode." > "$WATCH_DIR/file1.txt"
SHA1=$(sha256sum "$WATCH_DIR/file1.txt" | awk '{print $1}')

# Wait for sender to process and delete
for i in {1..30}; do
    if [ ! -e "$WATCH_DIR/file1.txt" ]; then break; fi
    sleep 0.2
done

if [ -e "$WATCH_DIR/file1.txt" ]; then
    echo "FAIL: file1.txt was not deleted from $WATCH_DIR after transmission!"
    exit 1
fi
echo "   -> File 1 sent and deleted from spool: OK"

# Check file1 in receiver
test -f "$RECV_DIR/file1.txt"
RECV_SHA1=$(sha256sum "$RECV_DIR/file1.txt" | awk '{print $1}')
if [ "$SHA1" != "$RECV_SHA1" ]; then
    echo "FAIL: Checksum mismatch for file1.txt"
    exit 1
fi
echo "   -> Receiver verified file1.txt SHA-256 match: OK"

echo "4. Dropping Directory Hierarchy into $WATCH_DIR..."
mkdir -p "$WATCH_DIR/batch_dir/sub"
echo "Batch text inside subtree" > "$WATCH_DIR/batch_dir/sub/text.txt"
python3 -c 'import os; open("'"$WATCH_DIR"'/batch_dir/random.bin", "wb").write(os.urandom(80000))'
ln -s "sub/text.txt" "$WATCH_DIR/batch_dir/link.txt"

SHA_BATCH_BIN=$(sha256sum "$WATCH_DIR/batch_dir/random.bin" | awk '{print $1}')

# Wait for sender to process and delete directory tree
for i in {1..40}; do
    if [ ! -e "$WATCH_DIR/batch_dir" ]; then break; fi
    sleep 0.2
done

if [ -e "$WATCH_DIR/batch_dir" ]; then
    echo "FAIL: batch_dir was not deleted from $WATCH_DIR after transmission!"
    exit 1
fi
echo "   -> Directory tree sent and purged from spool: OK"

# Check received subtree
test -f "$RECV_DIR/batch_dir/sub/text.txt"
test -L "$RECV_DIR/batch_dir/link.txt"
RECV_SHA_BIN=$(sha256sum "$RECV_DIR/batch_dir/random.bin" | awk '{print $1}')
if [ "$SHA_BATCH_BIN" != "$RECV_SHA_BIN" ]; then
    echo "FAIL: Checksum mismatch for batch_dir/random.bin"
    exit 1
fi
echo "   -> Receiver verified directory tree & symlink: OK"

echo "5. Dropping Multi-Block Binary File (500KB) into $WATCH_DIR..."
python3 -c 'import os; open("'"$WATCH_DIR"'/large.dat", "wb").write(os.urandom(500000))'
SHA_LARGE=$(sha256sum "$WATCH_DIR/large.dat" | awk '{print $1}')

for i in {1..50}; do
    if [ ! -e "$WATCH_DIR/large.dat" ]; then break; fi
    sleep 0.2
done

if [ -e "$WATCH_DIR/large.dat" ]; then
    echo "FAIL: large.dat was not deleted from $WATCH_DIR after transmission!"
    exit 1
fi
echo "   -> Large file sent and deleted from spool: OK"

RECV_SHA_LARGE=$(sha256sum "$RECV_DIR/large.dat" | awk '{print $1}')
if [ "$SHA_LARGE" != "$RECV_SHA_LARGE" ]; then
    echo "FAIL: Checksum mismatch for large.dat"
    exit 1
fi
echo "   -> Receiver verified 500KB multi-block file: OK"

echo ""
echo "=========================================================="
echo "=== ALL WATCH DIRECTORY TESTS PASSED 100%! ==="
echo "=========================================================="
