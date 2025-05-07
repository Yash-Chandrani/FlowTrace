import socket
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from io import StringIO

# Parameters
MAX_PACKETS = 10
WINDOW      = 50  # for anomaly detection; adjust or ignore if only demo

# Setup UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9999))
print(f"Listening for {MAX_PACKETS} packet lines on UDP port 9999…")

buffer = []
received = 0

try:
    while received < MAX_PACKETS:
        data, _ = sock.recvfrom(1024)
        line = data.decode().strip()
        print(f"[ANALYZER] Received: {line}", flush=True)
        buffer.append(line)
        received += 1

    print(f"Received {received} lines; exiting.")
except KeyboardInterrupt:
    print(f"\nInterrupted after {received} packets.")
finally:
    sock.close()
