#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "=== TESTING LINUX SERVICE DAEMON & CONFIG FILE MODE ==="
echo "=========================================================="

TMPDIR=$(mktemp -d /tmp/sxfer_daemon_test_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

BIN="./target/x86_64-unknown-linux-musl/release/sxfer"
if [ ! -f "$BIN" ]; then
    BIN="./target/release/sxfer"
fi
if [ ! -f "$BIN" ]; then
    cargo build --release
    BIN="./target/x86_64-unknown-linux-musl/release/sxfer"
    if [ ! -f "$BIN" ]; then
        BIN="./target/release/sxfer"
    fi
fi

PIPE="$TMPDIR/daemon_pipe"
CONF_RX="$TMPDIR/sxfer_rx.conf"
CONF_TX="$TMPDIR/sxfer_tx.conf"
RECV_DIR="$TMPDIR/recv_dest"
WATCH_DIR="$TMPDIR/watch_spool"

mkdir -p "$RECV_DIR" "$WATCH_DIR"
mkfifo "$PIPE"

# Write receiver config
cat <<EOF > "$CONF_RX"
[general]
role = receiver
port = $PIPE
baud = 115200
redundancy = 1.0

[receiver]
dest_dir = $RECV_DIR
keep_damaged = false
EOF

# Write sender config (watch mode)
cat <<EOF > "$CONF_TX"
[general]
role = sender
port = $PIPE
baud = 115200
redundancy = 1.0

[sender]
watch_dir = $WATCH_DIR
poll_interval_ms = 100
delete_after_send = true
EOF

echo "1. Starting receiver daemon with config $CONF_RX..."
"$BIN" daemon --config "$CONF_RX" &
RX_PID=$!
sleep 0.3

echo "2. Starting sender watch daemon with config $CONF_TX..."
"$BIN" daemon --config "$CONF_TX" &
TX_PID=$!
sleep 0.5

echo "3. Dropping payload file into watch directory..."
echo "Hello from Linux Service Daemon over sxfer!" > "$WATCH_DIR/service_test.txt"

# Wait for transmission & verification
sleep 2

echo "4. Verifying received file in destination directory..."
if [ ! -f "$RECV_DIR/service_test.txt" ]; then
    echo "ERROR: Received file missing in $RECV_DIR"
    kill -9 "$RX_PID" "$TX_PID" 2>/dev/null || true
    exit 1
fi

CONTENT=$(cat "$RECV_DIR/service_test.txt")
EXPECTED="Hello from Linux Service Daemon over sxfer!"
if [ "$CONTENT" != "$EXPECTED" ]; then
    echo "ERROR: Content mismatch! Got: '$CONTENT', Expected: '$EXPECTED'"
    kill -9 "$RX_PID" "$TX_PID" 2>/dev/null || true
    exit 1
fi

echo "   -> File content verified: OK ('$CONTENT')"

echo "5. Verifying watch spool cleanup..."
if [ -f "$WATCH_DIR/service_test.txt" ]; then
    echo "ERROR: Spool file not deleted after send!"
    kill -9 "$RX_PID" "$TX_PID" 2>/dev/null || true
    exit 1
fi
echo "   -> Spool file deleted after send: OK"

# Stop daemons
kill -TERM "$RX_PID" "$TX_PID" 2>/dev/null || true
wait "$RX_PID" 2>/dev/null || true
wait "$TX_PID" 2>/dev/null || true

echo "=========================================================="
echo "=== LINUX SERVICE DAEMON & CONFIG TESTS PASSED 100%! ==="
echo "=========================================================="
