#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import sys

filename = sys.argv[1]

regexp = re.compile("got inv: tx (\w+)")

txlist = set()
duplicates = 0
total = 0

with open(filename) as f:
    line = f.readline()
    while line:
        matches = regexp.search(line)
        if matches:
	    total += 1
	    hash = matches.group(1)
	    if hash in txlist:
		duplicates += 1
	    txlist.add(hash)
	line = f.readline()

print('Total: ' + str(total))
print('Duplicates: ' + str(duplicates))
