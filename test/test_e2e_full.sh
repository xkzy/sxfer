#!/bin/bash
set -e

SRC_DIR=$(mktemp -d /tmp/sxfer_e2e_src_XXXXXX)
DST_DIR=$(mktemp -d /tmp/sxfer_e2e_dst_XXXXXX)
PIPE=$(mktemp -u /tmp/sxfer_pipe_XXXXXX)
mkfifo "$PIPE"

cleanup() {
    rm -rf "$SRC_DIR" "$DST_DIR" "$PIPE"
}
trap cleanup EXIT

echo "=== Setting up test tree ==="
mkdir -p "$SRC_DIR/sub"
echo "Test file 1 content with repeating text to compress" > "$SRC_DIR/hello.txt"
python3 -c 'import os; open("'"$SRC_DIR"'/data.bin", "wb").write(b"RaptorQ " * 10000 + os.urandom(50000) + b"Fountain" * 10000)'
ln -s "../hello.txt" "$SRC_DIR/sub/link.txt"

# Calculate expected CRCs
CRC_HELLO=$(./sxfer crc "$SRC_DIR/hello.txt" | awk '{print $1}')
CRC_DATA=$(./sxfer crc "$SRC_DIR/data.bin" | awk '{print $1}')

echo "Expected CRC hello: $CRC_HELLO"
echo "Expected CRC data:  $CRC_DATA"

echo "=========================================================="
echo "=== Testing Pipeline Transfer with COBS + Scramble + L9 ==="
echo "=========================================================="
rm -rf "$DST_DIR"/*

./sxfer recv -d "$PIPE" -o "$DST_DIR" -q 2 &
RECV_PID=$!
sleep 0.5

(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$PIPE" -r 1 hello.txt data.bin sub)
wait $RECV_PID

diff -u "$SRC_DIR/hello.txt" "$DST_DIR/hello.txt"
diff -u "$SRC_DIR/data.bin" "$DST_DIR/data.bin"
test -L "$DST_DIR/sub/link.txt"
echo "Pipeline transfer PASSED!"

echo "=========================================================="
echo "=== Testing Rateless Fountain Decoding with 20% Packet Drops ==="
echo "=========================================================="
SPOOL=$(mktemp /tmp/sxfer_spool_XXXXXX)
CORRUPTED=$(mktemp /tmp/sxfer_corrupt_XXXXXX)

rm -rf "$DST_DIR"/*
# Generate fountain stream with 50% extra repair symbols (-f 50)
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -f 50 -r 1 hello.txt data.bin)

# Drop 20% of COBS packets at random
python3 -c '
import random
random.seed(42)

with open("'"$SPOOL"'", "rb") as f:
    data = f.read()

# Split by 0x00 delimiter
packets = data.split(b"\x00")
out = bytearray()
dropped = 0
kept = 0

for pkt in packets[:-1]:
    # Keep header packets, drop 25% of data symbol packets
    if len(pkt) > 100 and random.random() < 0.25:
        dropped += 1
        continue
    out.extend(pkt)
    out.append(0x00)
    kept += 1

with open("'"$CORRUPTED"'", "wb") as f:
    f.write(out)

print(f"Total packets: {len(packets)-1}, Kept: {kept}, Dropped: {dropped} ({dropped*100/(len(packets)-1):.1f}%)")
'

./sxfer recv -d "$CORRUPTED" -o "$DST_DIR" -q 1

diff -u "$SRC_DIR/hello.txt" "$DST_DIR/hello.txt"
diff -u "$SRC_DIR/data.bin" "$DST_DIR/data.bin"

echo "Fountain Loss Recovery PASSED!"
rm -f "$SPOOL" "$CORRUPTED"

echo "=========================================================="
echo "=== ALL END-TO-END VERIFICATION TESTS PASSED! ==="
echo "=========================================================="
