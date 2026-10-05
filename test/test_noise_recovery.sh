#!/bin/bash
set -e

SRC_DIR=$(mktemp -d /tmp/sxfer_noise_src_XXXXXX)
DST_DIR=$(mktemp -d /tmp/sxfer_noise_dst_XXXXXX)
SPOOL=$(mktemp /tmp/sxfer_spool_XXXXXX)
NOISY_STREAM=$(mktemp /tmp/sxfer_noisy_XXXXXX)

cleanup() {
    rm -rf "$SRC_DIR" "$DST_DIR" "$SPOOL" "$NOISY_STREAM"
}
trap cleanup EXIT

echo "=========================================================="
echo "=== Setting up Test Data for Noise Recovery Tests ==="
echo "=========================================================="
mkdir -p "$SRC_DIR/nested/deep"
echo "Small text file for testing metadata recovery under noise" > "$SRC_DIR/text.txt"
# Create a 200KB mixed binary file with repeating and random data
python3 -c '
import os
with open("'"$SRC_DIR"'/binary.dat", "wb") as f:
    f.write(b"HEADER_DATA_12345\n" * 500)
    f.write(os.urandom(100000))
    f.write(b"FOOTER_DATA_67890\n" * 500)
'
ln -s "../text.txt" "$SRC_DIR/nested/deep/symlink.txt"

CRC_TEXT=$(./sxfer crc "$SRC_DIR/text.txt" | awk '{print $1}')
CRC_BIN=$(./sxfer crc "$SRC_DIR/binary.dat" | awk '{print $1}')

echo "Source Text CRC:   $CRC_TEXT"
echo "Source Binary CRC: $CRC_BIN"

# -----------------------------------------------------------------------------
# Test 1: Random Frame Corruption & Bit Flipping Noise (15% Damaged Frames)
# -----------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "=== Test 1: Random Frame Corruption & Bit Flipping Noise ==="
echo "=========================================================="
rm -rf "$DST_DIR"/*
# Transmit with 50% extra RaptorQ repair symbols
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -f 50 -r 1 text.txt binary.dat nested)

python3 -c '
import random
random.seed(101)

with open("'"$SPOOL"'", "rb") as f:
    data = f.read()

packets = data.split(b"\x00")
out = bytearray()
corrupted_count = 0
clean_count = 0

for pkt in packets[:-1]:
    pkt_bytes = bytearray(pkt)
    # Corrupt 15% of packets by flipping bytes (simulating physical line bit errors)
    if len(pkt_bytes) > 100 and random.random() < 0.15:
        for _ in range(random.randint(1, 5)):
            idx = random.randint(0, len(pkt_bytes)-1)
            pkt_bytes[idx] ^= random.randint(1, 255)
            if pkt_bytes[idx] == 0: pkt_bytes[idx] = 0xAA
        corrupted_count += 1
    else:
        clean_count += 1

    out.extend(pkt_bytes)
    out.append(0x00)

with open("'"$NOISY_STREAM"'", "wb") as f:
    f.write(out)

print(f"Total Packets: {len(packets)-1}, Corrupted: {corrupted_count} ({corrupted_count*100/(len(packets)-1):.1f}%), Clean: {clean_count}")
'

./sxfer recv -d "$NOISY_STREAM" -o "$DST_DIR" -q 1

diff -u "$SRC_DIR/text.txt" "$DST_DIR/text.txt"
diff -u "$SRC_DIR/binary.dat" "$DST_DIR/binary.dat"
test -L "$DST_DIR/nested/deep/symlink.txt"
echo ">>> Test 1 (Random Frame Corruption Noise) PASSED 100%!"

# -----------------------------------------------------------------------------
# Test 2: Burst Impulse Noise (Garbage Byte Injection)
# -----------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "=== Test 2: Burst Impulse Noise & Line Garbage Injection ==="
echo "=========================================================="
rm -rf "$DST_DIR"/*
# Transmit with 40% repair symbols
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -f 40 -r 1 text.txt binary.dat nested)

python3 -c '
import random, os
random.seed(202)

with open("'"$SPOOL"'", "rb") as f:
    data = f.read()

# Split into COBS packets
packets = data.split(b"\x00")
out = bytearray()
injected_bursts = 0

for pkt in packets[:-1]:
    out.extend(pkt)
    out.append(0x00)
    # Inject burst noise between frames 20% of the time
    if random.random() < 0.20:
        burst_len = random.randint(50, 400)
        noise = bytearray(os.urandom(burst_len))
        for j in range(len(noise)):
            if noise[j] == 0: noise[j] = 0xAA
        out.extend(noise)
        out.append(0x00)
        injected_bursts += 1

with open("'"$NOISY_STREAM"'", "wb") as f:
    f.write(out)

print(f"Total Packets: {len(packets)-1}, Injected Noise Bursts: {injected_bursts}")
'

./sxfer recv -d "$NOISY_STREAM" -o "$DST_DIR" -q 1

diff -u "$SRC_DIR/text.txt" "$DST_DIR/text.txt"
diff -u "$SRC_DIR/binary.dat" "$DST_DIR/binary.dat"
test -L "$DST_DIR/nested/deep/symlink.txt"
echo ">>> Test 2 (Burst Impulse Noise) PASSED 100%!"

# -----------------------------------------------------------------------------
# Test 3: Heavy Packet Drop (30% Erasure Channel)
# -----------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "=== Test 3: Heavy Packet Drop (30% Erasure Channel) ==="
echo "=========================================================="
rm -rf "$DST_DIR"/*
# Transmit with 60% repair symbols
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -f 60 -r 1 text.txt binary.dat nested)

python3 -c '
import random
random.seed(303)

with open("'"$SPOOL"'", "rb") as f:
    data = f.read()

packets = data.split(b"\x00")
out = bytearray()
kept = 0
dropped = 0

for pkt in packets[:-1]:
    # Keep metadata header packets, randomly drop 30% of data symbol packets
    if len(pkt) > 100 and random.random() < 0.30:
        dropped += 1
        continue
    out.extend(pkt)
    out.append(0x00)
    kept += 1

with open("'"$NOISY_STREAM"'", "wb") as f:
    f.write(out)

print(f"Total Symbol Packets: {len(packets)-1}, Kept: {kept}, Dropped: {dropped} ({dropped*100/(len(packets)-1):.1f}%)")
'

./sxfer recv -d "$NOISY_STREAM" -o "$DST_DIR" -q 1

diff -u "$SRC_DIR/text.txt" "$DST_DIR/text.txt"
diff -u "$SRC_DIR/binary.dat" "$DST_DIR/binary.dat"
test -L "$DST_DIR/nested/deep/symlink.txt"
echo ">>> Test 3 (30% Packet Drop Erasure Channel) PASSED 100%!"

# -----------------------------------------------------------------------------
# Test 4: Severe Combined Channel Degradation (Drops + Bit Flips + Burst Noise)
# -----------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "=== Test 4: Severe Combined Degradation (Drops + Corruption + Bursts) ==="
echo "=========================================================="
rm -rf "$DST_DIR"/*
# Transmit with 70% repair symbols and 2 rounds
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -f 70 -r 2 text.txt binary.dat nested)

python3 -c '
import random, os
random.seed(404)

with open("'"$SPOOL"'", "rb") as f:
    data = f.read()

packets = data.split(b"\x00")
out = bytearray()
kept = 0
dropped = 0
corrupted = 0
bursts = 0

for pkt in packets[:-1]:
    # 1. 20% packet drop
    if len(pkt) > 100 and random.random() < 0.20:
        dropped += 1
        continue

    pkt_bytes = bytearray(pkt)
    # 2. 10% probability of internal bit flips
    if len(pkt_bytes) > 100 and random.random() < 0.10:
        for _ in range(random.randint(1, 5)):
            idx = random.randint(0, len(pkt_bytes)-1)
            pkt_bytes[idx] ^= random.randint(1, 255)
            if pkt_bytes[idx] == 0: pkt_bytes[idx] = 0x55
        corrupted += 1

    out.extend(pkt_bytes)
    out.append(0x00)
    kept += 1

    # 3. 10% probability of burst noise injection
    if random.random() < 0.10:
        burst = bytearray(os.urandom(random.randint(30, 200)))
        for j in range(len(burst)):
            if burst[j] == 0: burst[j] = 0xBE
        out.extend(burst)
        out.append(0x00)
        bursts += 1

with open("'"$NOISY_STREAM"'", "wb") as f:
    f.write(out)

print(f"Packets: {len(packets)-1} -> Kept: {kept}, Dropped: {dropped}, Damaged: {corrupted}, Bursts Injected: {bursts}")
'

./sxfer recv -d "$NOISY_STREAM" -o "$DST_DIR" -q 1

diff -u "$SRC_DIR/text.txt" "$DST_DIR/text.txt"
diff -u "$SRC_DIR/binary.dat" "$DST_DIR/binary.dat"
test -L "$DST_DIR/nested/deep/symlink.txt"
echo ">>> Test 4 (Severe Combined Channel Degradation) PASSED 100%!"

# -----------------------------------------------------------------------------
# Test 5: Extreme 80% Packet Drop (80% Erasure Channel)
# -----------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "=== Test 5: Extreme 80% Packet Drop (80% Erasure Channel) ==="
echo "=========================================================="
rm -rf "$DST_DIR"/*
# Transmit with 450% repair fountain overhead (enough to recover from 80% drops)
(cd "$SRC_DIR" && /home/khing/Desktop/sxfer/sxfer send -d "$SPOOL" -f 450 -r 1 text.txt binary.dat nested)

python3 -c '
import random
random.seed(606)

with open("'"$SPOOL"'", "rb") as f:
    data = f.read()

packets = data.split(b"\x00")
out = bytearray()
kept = 0
dropped = 0

for pkt in packets[:-1]:
    # Randomly drop 80% of packets across the board
    if random.random() < 0.80:
        dropped += 1
        continue
    out.extend(pkt)
    out.append(0x00)
    kept += 1

with open("'"$NOISY_STREAM"'", "wb") as f:
    f.write(out)

total = len(packets) - 1
print(f"Total Packets: {total} -> Kept: {kept} ({kept*100/total:.1f}%), Dropped: {dropped} ({dropped*100/total:.1f}%)")
'

./sxfer recv -d "$NOISY_STREAM" -o "$DST_DIR" -q 1

diff -u "$SRC_DIR/text.txt" "$DST_DIR/text.txt"
diff -u "$SRC_DIR/binary.dat" "$DST_DIR/binary.dat"
test -L "$DST_DIR/nested/deep/symlink.txt"
echo ">>> Test 5 (Extreme 80% Packet Drop) PASSED 100%!"

echo ""
echo "=========================================================="
echo "=== ALL 5 NOISE & EXTREME ERASURE TESTS PASSED 100%! ==="
echo "=========================================================="
