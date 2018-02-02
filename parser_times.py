#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import sys

filename = sys.argv[1]

regexp_message = re.compile("message processing (.*)")
regexp_txhash = re.compile("txhash: tx (.*)")
regexp_timestamp = re.compile("now: (.*)")
regexp_peer = re.compile("peer: (.*)")
regexp_already_have = re.compile("alreadyHave: (.*)")


def parseValue(data, regexp):
    matches = regexp.search(data)
    if matches:
        return matches.group(1)
    return ""

tx_processing_times = dict()
tx_timestamps = dict()
tx_peers = dict()
peers_duplicates = dict()

with open(filename) as f:
    line = f.readline()
    while line:
        data = parseValue(line, regexp_message)
        if data:
            timedata, txtypedata, txhashdata, txtimestampdata, txpeerdata = data.split(", ")
            txtype = txtypedata.split(": ")[1]
            if txtype != "inv":
                pass
            time = timedata.split(": ")[1]
            txhash = parseValue(txhashdata, regexp_txhash)
            timestamp = parseValue(txtimestampdata, regexp_timestamp)
            peer = parseValue(txpeerdata, regexp_peer)
            # already_have = parseValue(txalreadyhave)
            if txhash == "" or timestamp == "":
                pass
            if not tx_processing_times.get(txhash):
                tx_timestamps[txhash] = timestamp
                tx_processing_times[txhash] = []
            tx_processing_times[txhash].append(float(time))

            if not tx_peers.get(txhash):
                tx_peers[txhash] = []
            tx_peers[txhash].append(peer)

        line = f.readline()



totals = [0]*10
times_between_messages = []

processing_times = []


for key in sorted(tx_processing_times, key = lambda hash: len(tx_processing_times[hash])):
    v = tx_processing_times[key]
    duplicates = len(v)
    totals[duplicates] += 1

    processing_times.extend(v)

    ordered_times = sorted(v)
    for i in range (len(ordered_times)-2, 0):
        ordered_times[i+1] -= ordered_times[i]
    ordered_times[0] = 0
    times_between_messages.extend(ordered_times[1:])

    for peer in tx_peers[key]:
        if not peers_duplicates.get(peer):
            peers_duplicates[peer] = [0] * 10
        peers_duplicates[peer][duplicates] += 1

    # print(key)
    # print("Times: {times}, sum: {sumv}, sum w/o max: {sumwomax}, timestamp: {timestamp}".
    #     format(times=duplicates, sumv=sum(v), sumwomax=sum(v)-max(v), timestamp=tx_timestamps[key]))
    # print("Time between messages: {ordered_times}".format(ordered_times=ordered_times))


print("Totals: {totals}".format(totals=totals))


total_times_between = [0] * 150
for time in times_between_messages:
    total_times_between[int(time)] += 1



total_processing_times = [0] * 150
for time in processing_times:
    total_processing_times[int(time)] += 1



print("Times between messages: {times}".format(times=total_times_between))
print("Average time between messages: {avg_time}".format(avg_time=sum(times_between_messages)/len(times_between_messages)))


print("Times processing messages: {times}".format(times=total_processing_times))
print("Average processing time: {avg_time}".format(avg_time=sum(processing_times)/len(processing_times)))


for key in peers_duplicates:
    print("Peer {peer} duplicate-wise: {dups}".format(peer=key, dups=peers_duplicates[key]))
