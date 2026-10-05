#!/bin/bash
set -e

echo "=========================================================="
echo "=== SXFER FULL REGRESSION SUITE ==="
echo "=========================================================="

SRC_DIR=$(mktemp -d /tmp/sxfer_reg_src_XXXXXX)
DST_DIR=$(mktemp -d /tmp/sxfer_reg_dst_XXXXXX)
PIPE=$(mktemp -u /tmp/sxfer_reg_pipe_XXXXXX)
SPOOL=$(mktemp /tmp/sxfer_reg_spool_XXXXXX)
NOISY=$(mktemp /tmp/sxfer_reg_noisy_XXXXXX)
mkfifo "$PIPE"

cleanup() {
    rm -rf "$SRC_DIR" "$DST_DIR" "$PIPE" "$SPOOL" "$NOISY"
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# 1. Generate Diverse Test Data Tree
# -----------------------------------------------------------------------------
echo "[1/7] Generating diverse test data tree..."
mkdir -p "$SRC_DIR/empty_dir"
mkdir -p "$SRC_DIR/nested/level1/level2/level3"

# Small text file
echo "Small text payload for metadata and framing tests." > "$SRC_DIR/small.txt"
chmod 0644 "$SRC_DIR/small.txt"

# Executable script
echo -e '#!/bin/sh\necho "Hello from sxfer executable!"' > "$SRC_DIR/nested/script.sh"
chmod 0755 "$SRC_DIR/nested/script.sh"

# Read-only config file
echo "READONLY_SETTING=1" > "$SRC_DIR/nested/readonly.cfg"
chmod 0444 "$SRC_DIR/nested/readonly.cfg"

# Highly compressible text file (1 MB)
python3 -c '
with open("'"$SRC_DIR"'/nested/level1/compressible.txt", "w") as f:
    for i in range(25000):
        f.write(f"Line {i}: The quick brown fox jumps over the lazy dog 1234567890\n")
'

# High-entropy / mixed binary file (2.5 MB - Multi-Block RaptorQ)
python3 -c '
import os
with open("'"$SRC_DIR"'/nested/level1/level2/level3/large_multiblock.bin", "wb") as f:
    f.write(b"MULTIBLOCK_START\n" * 2000)
    f.write(os.urandom(1500000))
    f.write(b"MULTIBLOCK_MIDDLE\n" * 2000)
    f.write(os.urandom(1000000))
    f.write(b"MULTIBLOCK_END\n")
'

# Symlinks
ln -s "../../small.txt" "$SRC_DIR/nested/level1/symlink_rel.txt"
ln -s "script.sh" "$SRC_DIR/nested/symlink_sibling.sh"

# Calculate ground-truth checksums
SRC_SHA=$(cd "$SRC_DIR" && find . -type f | sort | xargs sha256sum)
echo "Generated $(find "$SRC_DIR" | wc -l) filesystem items."

# -----------------------------------------------------------------------------
# 2. Compression Level Regression (Level 0, 1, 6, 9)
# -----------------------------------------------------------------------------
echo ""
echo "[2/7] Testing Fast-LZMA2 Compression Levels (0, 1, 6, 9)..."
for lvl in 0 1 6 9; do
    rm -rf "$DST_DIR"/*
    echo "  -> Testing -z $lvl..."
    ./sxfer recv -d "$PIPE" -o "$DST_DIR" -m cobs -q 2 &
    RECV_PID=$!
    sleep 0.3

    (cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$PIPE" -m cobs -z "$lvl" -r 1 small.txt nested empty_dir)
    wait $RECV_PID

    DST_SHA=$(cd "$DST_DIR" && find . -type f | sort | xargs sha256sum)
    if [ "$SRC_SHA" != "$DST_SHA" ]; then
        echo "FAIL: Checksum mismatch at -z $lvl"
        exit 1
    fi
    test -d "$DST_DIR/empty_dir"
    test -L "$DST_DIR/nested/level1/symlink_rel.txt"
    echo "     Level -z $lvl: OK"
done

# -----------------------------------------------------------------------------
# 3. Modulation & Baseband Framing Modes (cobs, scramble, raw)
# -----------------------------------------------------------------------------
echo ""
echo "[3/7] Testing Baseband Framing Modes (cobs, scramble, raw)..."
for mod in cobs scramble raw; do
    rm -rf "$DST_DIR"/*
    echo "  -> Testing -m $mod..."
    ./sxfer recv -d "$PIPE" -o "$DST_DIR" -m "$mod" -q 2 &
    RECV_PID=$!
    sleep 0.3

    (cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$PIPE" -m "$mod" -z 6 -r 1 small.txt nested empty_dir)
    wait $RECV_PID

    DST_SHA=$(cd "$DST_DIR" && find . -type f | sort | xargs sha256sum)
    if [ "$SRC_SHA" != "$DST_SHA" ]; then
        echo "FAIL: Checksum mismatch at -m $mod"
        exit 1
    fi
    echo "     Mode -m $mod: OK"
done

# -----------------------------------------------------------------------------
# 4. Adaptive Baud Rates & Symbol Chunk Sizes (1k, 4k, 16k)
# -----------------------------------------------------------------------------
echo ""
echo "[4/7] Testing Baud Rates & Chunk Sizing (115200, 921600, 4000000)..."
for baud in 115200 921600 4000000; do
    rm -rf "$DST_DIR"/*
    echo "  -> Testing -b $baud..."
    ./sxfer recv -d "$PIPE" -o "$DST_DIR" -b "$baud" -m cobs -q 2 &
    RECV_PID=$!
    sleep 0.3

    (cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$PIPE" -b "$baud" -m cobs -z 6 -r 1 small.txt nested empty_dir)
    wait $RECV_PID

    DST_SHA=$(cd "$DST_DIR" && find . -type f | sort | xargs sha256sum)
    if [ "$SRC_SHA" != "$DST_SHA" ]; then
        echo "FAIL: Checksum mismatch at -b $baud"
        exit 1
    fi
    echo "     Baud -b $baud: OK"
done

# -----------------------------------------------------------------------------
# 5. Multi-Block Large File Transfer (2.5MB File Verification)
# -----------------------------------------------------------------------------
echo ""
echo "[5/7] Testing Multi-Block RaptorQ (2.5MB payload over 25+ RaptorQ blocks)..."
rm -rf "$DST_DIR"/*
./sxfer recv -d "$PIPE" -o "$DST_DIR" -m cobs -q 2 &
RECV_PID=$!
sleep 0.3

(cd "$SRC_DIR/nested/level1/level2/level3" && /home/khing/Desktop/sxfer/sxfer send -d "$PIPE" -m cobs -z 6 -r 1 large_multiblock.bin)
wait $RECV_PID

diff -u "$SRC_DIR/nested/level1/level2/level3/large_multiblock.bin" "$DST_DIR/large_multiblock.bin"
echo "     Multi-block 2.5MB file transfer: 100% Bit-Exact Match!"

# -----------------------------------------------------------------------------
# 6. Metadata, File Mode Permissions & Symlink Integrity
# -----------------------------------------------------------------------------
echo ""
echo "[6/7] Verifying Permissions & Symlinks..."
rm -rf "$DST_DIR"/*
./sxfer recv -d "$PIPE" -o "$DST_DIR" -m cobs -q 2 &
RECV_PID=$!
sleep 0.3

(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$PIPE" -m cobs -z 6 -r 1 small.txt nested empty_dir)
wait $RECV_PID

# Verify file permissions preserved
test "$(stat -c %a "$DST_DIR/nested/script.sh" 2>/dev/null || stat -f %Lp "$DST_DIR/nested/script.sh")" = "755"
test "$(stat -c %a "$DST_DIR/nested/readonly.cfg" 2>/dev/null || stat -f %Lp "$DST_DIR/nested/readonly.cfg")" = "444"
test -L "$DST_DIR/nested/level1/symlink_rel.txt"
test "$(readlink "$DST_DIR/nested/level1/symlink_rel.txt")" = "../../small.txt"
echo "     Permissions (0755, 0444) & Symlinks: OK"


# -----------------------------------------------------------------------------
# 7. Erasure & Noise Channel Spectrum (0% -> 80% Drops + Corruptions)
# -----------------------------------------------------------------------------
echo ""
echo "[7/7] Testing Erasure Spectrum & Noise Resistance..."

# 7a. 10% packet drop
echo "  -> 10% Erasure Channel..."
rm -rf "$DST_DIR"/*
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -m cobs -f 25 -z 6 -r 1 small.txt nested/script.sh)
python3 -c '
import random
random.seed(701)
with open("'"$SPOOL"'", "rb") as f: data = f.read()
pkts = data.split(b"\x00")
out = bytearray()
for p in pkts[:-1]:
    if len(p) > 100 and random.random() < 0.10: continue
    out.extend(p); out.append(0x00)
with open("'"$NOISY"'", "wb") as f: f.write(out)
'
./sxfer recv -d "$NOISY" -o "$DST_DIR" -m cobs -q 1
diff -u "$SRC_DIR/nested/script.sh" "$DST_DIR/nested/script.sh"
echo "     10% Loss: OK"

# 7b. 50% packet drop
echo "  -> 50% Erasure Channel..."
rm -rf "$DST_DIR"/*
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -m cobs -f 150 -z 6 -r 1 small.txt nested/script.sh)
python3 -c '
import random
random.seed(702)
with open("'"$SPOOL"'", "rb") as f: data = f.read()
pkts = data.split(b"\x00")
out = bytearray()
for p in pkts[:-1]:
    if len(p) > 100 and random.random() < 0.50: continue
    out.extend(p); out.append(0x00)
with open("'"$NOISY"'", "wb") as f: f.write(out)
'
./sxfer recv -d "$NOISY" -o "$DST_DIR" -m cobs -q 1
diff -u "$SRC_DIR/nested/script.sh" "$DST_DIR/nested/script.sh"
echo "     50% Loss: OK"

# 7c. 80% packet drop
echo "  -> 80% Extreme Erasure Channel..."
rm -rf "$DST_DIR"/*
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -m cobs -f 450 -z 6 -r 1 small.txt nested/script.sh)
python3 -c '
import random
random.seed(703)
with open("'"$SPOOL"'", "rb") as f: data = f.read()
pkts = data.split(b"\x00")
out = bytearray()
for p in pkts[:-1]:
    if random.random() < 0.80: continue
    out.extend(p); out.append(0x00)
with open("'"$NOISY"'", "wb") as f: f.write(out)
'
./sxfer recv -d "$NOISY" -o "$DST_DIR" -m cobs -q 1
diff -u "$SRC_DIR/nested/script.sh" "$DST_DIR/nested/script.sh"
echo "     80% Loss: OK"

# 7d. Line Corruptions + Burst Garbage
echo "  -> Combined Bit Corruption (15%) & Burst Injection (20%)..."
rm -rf "$DST_DIR"/*
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -m cobs -f 60 -z 6 -r 1 small.txt nested/script.sh)
python3 -c '
import random, os
random.seed(704)
with open("'"$SPOOL"'", "rb") as f: data = f.read()
pkts = data.split(b"\x00")
out = bytearray()
for p in pkts[:-1]:
    b = bytearray(p)
    if len(b) > 100 and random.random() < 0.15:
        b[random.randint(0, len(b)-1)] ^= random.randint(1, 255)
    out.extend(b); out.append(0x00)
    if random.random() < 0.20:
        noise = bytearray(os.urandom(random.randint(50, 200)))
        for i in range(len(noise)):
            if noise[i] == 0: noise[i] = 0xAA
        out.extend(noise); out.append(0x00)
with open("'"$NOISY"'", "wb") as f: f.write(out)
'
./sxfer recv -d "$NOISY" -o "$DST_DIR" -m cobs -q 1
diff -u "$SRC_DIR/nested/script.sh" "$DST_DIR/nested/script.sh"
echo "     Corruption & Bursts: OK"

echo ""
echo "=========================================================="
echo "=== ALL REGRESSION SUITE TESTS PASSED 100%! ==="
echo "=========================================================="
