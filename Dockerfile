# 1) Base image with C++ build tools, libpcap, Python
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# 2) Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential libpcap-dev \
      python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 3) Copy source and scripts
COPY main.cpp udp_listener.py requirements.txt entrypoint.sh ./

# 4) Build the C++ agent
RUN g++ -O3 -std=c++17 main.cpp -lpcap -o flowtrace

# 5) Install Python requirements
RUN pip3 install --no-cache-dir -r requirements.txt

# 6) Make entrypoint executable
RUN chmod +x entrypoint.sh

# 7) Run the unified entrypoint
ENTRYPOINT ["./entrypoint.sh"]