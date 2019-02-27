#!/usr/bin/python

import sys
import re
from dateutil.parser import parse
from statistics import mean

base_path = "/node%i/regtest/debug.log"

full_paths = []

NODES = 5

for i in range(NODES):
    new_path = sys.argv[1] + (base_path % i)
    full_paths.append(new_path)

print(full_paths)

tx_timestamps = dict()


received_bytes = [0] * NODES
sent_bytes = [0] * NODES

# parsing
i = 0
for path in full_paths:
    with open(path, "r") as btc_log:
        for line in btc_log:
            if 'AcceptToMemoryPool' in line:
                tx = line[line.find("accepted ") + 9 : line.find(" (")]
                time = line[:line.find("AcceptToMemoryPool")]
                time = parse(time).timestamp()
                if not tx in tx_timestamps:
                    tx_timestamps[tx] = [time]
                else:
                    tx_timestamps[tx].append(time)
            if 'received: ' in line and 'bytes' in line:
                bytes = int(line[line.find("(") + 1: line.find(" bytes)")])
                received_bytes[i] += bytes
            if 'sending ' in line and 'bytes' in line:
                bytes = int(line[line.find("(") + 1: line.find(" bytes)")])
                sent_bytes[i] += bytes
    i+=1


# analysis
latencies = []


for tx, times in tx_timestamps.items():
    if len(times) < NODES:
        continue
    times.sort()
    full_latency = times[-1] - times[0]
    latencies.append(full_latency)

# print(latencies)

print('Mean latency: ', mean(latencies))
print('Sent bytes: ', sent_bytes, sum(sent_bytes) /1024)
print('Received bytes: ', received_bytes, sum(received_bytes) / 1024)
