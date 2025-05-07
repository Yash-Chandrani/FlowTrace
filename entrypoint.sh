#!/bin/sh
set -e

echo "=== Starting Python analyzer in background ==="
python3 udp_listener.py &
ANALYZER_PID=$!

echo "=== Running FlowTrace C++ agent ==="
/app/flowtrace

echo "=== C++ agent exited, waiting for analyzer ==="
wait $ANALYZER_PID

echo "=== All done. Container will now exit ==="
