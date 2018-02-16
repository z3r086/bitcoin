#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import sys

filename = sys.argv[1]

regexp_message = re.compile("message processing (.*)")
regexp_msgtype = re.compile("msgtype: (.*)")
regexp_txhash = re.compile("txhash: (.*)")
regexp_time = re.compile("time: (.*)")
regexp_timestamp = re.compile("now: (.*)")
regexp_peer = re.compile("peer: (.*)")
regexp_already_have = re.compile("alreadyHave: (.*)")
regexp_size = re.compile("msgsize: (.*)")


def parseValue(data, regexp):
    matches = regexp.search(data)
    if matches:
        return matches.group(1)
    return ""

full_tx_processing_times = []
full_tx_sizes = []

tx_processing_times = dict()
tx_timestamps = dict()
tx_peers = dict()
peers_duplicates = dict()

first_time_times = []
dup_times = []


with open(filename) as f:
    line = f.readline()
    while line:
        data = parseValue(line, regexp_message)
        if data:
            # print(data)
            timedata, msgtypedata, txhashdata, txtimestampdata, txpeerdata, txalreadyhave, msgsizedata = data.split(", ")
            msgtype = parseValue(msgtypedata, regexp_msgtype)
            time = parseValue(timedata, regexp_time)
            txhash = parseValue(txhashdata, regexp_txhash)
            timestamp = parseValue(txtimestampdata, regexp_timestamp)
            peer = parseValue(txpeerdata, regexp_peer)
            already_have = parseValue(txalreadyhave, regexp_already_have)
            msg_size = parseValue(msgsizedata, regexp_size)
            if txhash == "" or timestamp == "":
                print(txhashdata)
                pass
            if msgtype == "tx":
                full_tx_processing_times.append(float(time))
                full_tx_sizes.append(int(msg_size))
            elif msgtype == "inv":
                if not tx_processing_times.get(txhash):
                    tx_timestamps[txhash] = timestamp
                    tx_processing_times[txhash] = []
                tx_processing_times[txhash].append(float(time))

                if not tx_peers.get(txhash):
                    tx_peers[txhash] = []
                tx_peers[txhash].append(peer)

                if already_have == '0':
                    first_time_times.append(float(time))
                else:
                    dup_times.append(float(time))
        line = f.readline()



totals = [0]*10
times_between_dups_and_orig = []

processing_times = []


for key in sorted(tx_processing_times, key = lambda hash: len(tx_processing_times[hash])):
    v = tx_processing_times[key]
    duplicates = len(v)
    if duplicates > 10:
        print(key)
        continue

    totals[duplicates] += 1

    processing_times.extend(v)

    ordered_times = sorted(v)
    first_time_heard = ordered_times[0]
    for i in range (1, ):
        ordered_times[i] -= first_time_heard
    times_between_dups_and_orig.extend(ordered_times[1:])

    for peer in tx_peers[key]:
        if not peers_duplicates.get(peer):
            peers_duplicates[peer] = [0] * 10
        peers_duplicates[peer][duplicates] += 1

        # print(key)
        # print("Times: {times}, sum: {sumv}, sum w/o max: {sumwomax}, timestamp: {timestamp}".
        #     format(times=duplicates, sumv=sum(v), sumwomax=sum(v)-max(v), timestamp=tx_timestamps[key]))
        # print("Time between messages: {ordered_times}".format(ordered_times=ordered_times))


print("Totals: {totals}".format(totals=totals))


total_times_between = [0] * 5000
for time in times_between_dups_and_orig:
    total_times_between[int(time/1000)] += 1



total_processing_times = [0] * 5000
for time in processing_times:
    total_processing_times[int(time/1000)] += 1



# print("Times btw messages distribution in ms: {times}".format(times=total_times_between))
print("Average time between messages: {avg_time} microseconds".format(avg_time=sum(times_between_dups_and_orig)/len(times_between_dups_and_orig)))


# Add also regular message processing
# And bandwidth
# And on mainnet
print("Average processing time: {avg_time} microseconds".format(avg_time=sum(processing_times)/len(processing_times)))
# print("Times processing messages distribution in microseconds: {times}".format(times=total_processing_times))

print("Average processing time (fulltx): {avg_time} microseconds"
     .format(avg_time=sum(full_tx_processing_times)/len(full_tx_processing_times)))
print("Average message size (fulltx): {avg_size} bytes"
      .format(avg_size=sum(full_tx_sizes)/len(full_tx_sizes)))


print("Average processing time for !dup!: {avg_time} microseconds".format(avg_time=sum(dup_times)/len(dup_times)))
print("Average processing time for !first!: {avg_time} microseconds".format(avg_time=sum(first_time_times)/len(first_time_times)))


#for key in peers_duplicates:
#    print("Peer {peer} duplicate-wise: {dups}".format(peer=key, dups=peers_duplicates[key]))
