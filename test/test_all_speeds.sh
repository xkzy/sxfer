#!/usr/bin/env bash
set -e

TX_DEV="/dev/ttyUSB0"
RX_DEV="/dev/ttyUSB1"

if [ ! -e "$TX_DEV" ] || [ ! -e "$RX_DEV" ]; then
    echo "ERROR: Serial devices $TX_DEV or $RX_DEV not found."
    exit 1
fi

BAUD_RATES=(
    3000000
    2000000
    1500000
    1152000
    1000000
    921600
    576000
    500000
    460800
    230400
    115200
    57600
    38400
    19200
    9600
    4800
    2400
    1200
)

BIN="./sxfer"

echo "================================================================================================================================================="
echo "                                              SXFER FULL SPECTRUM HARDWARE DATA RATE & ALGORITHM BENCHMARK                                       "
echo "                                              Transmitter: $TX_DEV   --->   Receiver: $RX_DEV                                                    "
echo "================================================================================================================================================="
printf "%-10s | %-9s | %-8s | %-11s | %-11s | %-16s | %-13s | %-17s | %-10s\n" \
    "Baud Rate" "Payload" "Time" "Real Rate" "Wire Rate" "Fast-LZMA2 L9" "SC-LDPC FEC" "RaptorQ (Rx/Req)" "Integrity"
echo "-------------------------------------------------------------------------------------------------------------------------------------------------"

PASSED_COUNT=0
FAILED_COUNT=0

for baud in "${BAUD_RATES[@]}"; do
    IN_DIR="/tmp/sxfer_bench_in_${baud}"
    OUT_DIR="/tmp/sxfer_bench_out_${baud}"
    LOG_RECV="/tmp/sxfer_bench_recv_${baud}.log"
    LOG_SEND="/tmp/sxfer_bench_send_${baud}.log"

    rm -rf "$IN_DIR" "$OUT_DIR" "$LOG_RECV" "$LOG_SEND"
    mkdir -p "$IN_DIR" "$OUT_DIR"

    if [ "$baud" -le 2400 ]; then
        PAYLOAD_BYTES=100
        IDLE_TIMEOUT=4
    elif [ "$baud" -le 9600 ]; then
        PAYLOAD_BYTES=200
        IDLE_TIMEOUT=3
    elif [ "$baud" -le 19200 ]; then
        PAYLOAD_BYTES=300
        IDLE_TIMEOUT=2
    elif [ "$baud" -le 57600 ]; then
        PAYLOAD_BYTES=1000
        IDLE_TIMEOUT=2
    elif [ "$baud" -le 230400 ]; then
        PAYLOAD_BYTES=8192
        IDLE_TIMEOUT=2
    elif [ "$baud" -le 1000000 ]; then
        PAYLOAD_BYTES=32768
        IDLE_TIMEOUT=2
    else
        PAYLOAD_BYTES=65536
        IDLE_TIMEOUT=2
    fi

    # Generate structured, realistic compressible payload
    python3 -c "
import sys
size = $PAYLOAD_BYTES
pattern = b'SXFER-V2-ALGORITHM-BENCHMARK-TELEMETRY-TEST-PACKET-DATA-0123456789\n'
data = (pattern * (size // len(pattern) + 1))[:size]
with open('$IN_DIR/bench.dat', 'wb') as f:
    f.write(data)
"

    # Start receiver
    $BIN recv -d "$RX_DEV" -b "$baud" -o "$OUT_DIR" -q "$IDLE_TIMEOUT" > "$LOG_RECV" 2>&1 &
    RECV_PID=$!
    sleep 0.35

    # Measure time
    START_NS=$(date +%s%N)
    $BIN send -d "$TX_DEV" -b "$baud" "$IN_DIR/bench.dat" > "$LOG_SEND" 2>&1 || true
    wait $RECV_PID || true
    END_NS=$(date +%s%N)

    ELAPSED_NS=$((END_NS - START_NS))
    if [ "$ELAPSED_NS" -lt 1000000 ]; then ELAPSED_NS=1000000; fi
    ELAPSED_SEC=$(python3 -c "print(f'{$ELAPSED_NS / 1_000_000_000:.3f}s')")

    DST_FILE="$OUT_DIR/bench.dat"
    if [ -f "$DST_FILE" ] && cmp -s "$IN_DIR/bench.dat" "$DST_FILE"; then
        RATE_KB=$(python3 -c "print(f'{$PAYLOAD_BYTES / ($ELAPSED_NS / 1_000_000_000) / 1024:.2f} KB/s')")
        THEO_KB=$(python3 -c "print(f'{$baud / 10 / 1024:.2f} KB/s')")

        # Parse metrics from receiver log
        LZMA_SAVINGS=$(grep -o "Fast-LZMA2: [^]]*" "$LOG_RECV" | sed 's/Fast-LZMA2: //' | grep -o '([0-9.]*%' | tr -d '(' || echo "0%")
        if [ -z "$LZMA_SAVINGS" ]; then LZMA_SAVINGS="0%"; fi
        LZMA_INFO="L9 (${LZMA_SAVINGS} saved)"

        LDPC_FLIPS=$(grep -o "SC-LDPC: [^]]*" "$LOG_RECV" | sed 's/SC-LDPC: //' | grep -o '^[0-9]*' || echo "0")
        if [ -z "$LDPC_FLIPS" ]; then LDPC_FLIPS="0"; fi
        LDPC_INFO="${LDPC_FLIPS} bit flips"

        RQ_INFO=$(grep -o "RaptorQ: [^]]*" "$LOG_RECV" | sed 's/RaptorQ: //' | sed 's/ source symbols needed.*//' | sed 's/ symbols received \/ / \/ /' || echo "N/A")
        if [ -z "$RQ_INFO" ]; then RQ_INFO="N/A"; fi

        printf "%-10s | %-9s | %-8s | %-11s | %-11s | %-16s | %-13s | %-17s | \033[32mPASSED\033[0m\n" \
            "$baud" "$PAYLOAD_BYTES B" "${ELAPSED_SEC}" "$RATE_KB" "$THEO_KB" "$LZMA_INFO" "$LDPC_INFO" "$RQ_INFO"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        printf "%-10s | %-9s | %-8s | %-11s | %-11s | %-16s | %-13s | %-17s | \033[31mFAILED\033[0m\n" \
            "$baud" "$PAYLOAD_BYTES B" "${ELAPSED_SEC}" "N/A" "N/A" "N/A" "N/A" "N/A"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi

    rm -rf "$IN_DIR" "$OUT_DIR" "$LOG_RECV" "$LOG_SEND"
done

echo "================================================================================================================================================="
echo "Summary: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed out of ${#BAUD_RATES[@]} baud rates tested."
echo "================================================================================================================================================="
