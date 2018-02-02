#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import sys

filename = sys.argv[1]

regexp = re.compile("Node (\w+)")

txlist = set()
duplicates = 0
total = 0

with open(filename) as f:
    line = f.readline()
    while line:
        matches = regexp.search(line)
        if matches:
            print(matches.group(1))
        line = f.readline()

