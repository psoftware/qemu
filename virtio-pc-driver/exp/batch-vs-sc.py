#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math


description = "Python script to compute mean and standard deviation"
epilog = "2016 Vincenzo Maffione"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-d', '--data-file',
                       help = "Path to file containing data", type=str,
                       required = True)

args = argparser.parse_args()

x=[]
y=[]

fin = open(args.data_file)
while 1:
    line = fin.readline()
    if line == '':
        break

    m = re.search(r'(\d+) items/s (\d+) kicks/s (\d+) sleeps/s (\d+) intrs/s (\d+) latency', line)
    if m == None:
        continue

    items = int(m.group(1))
    kicks = int(m.group(2))
    sc = int(m.group(5))

    if kicks != 0:
        x.append(sc)
        y.append(items/kicks)

fin.close()

for i in range(len(x)):
    print("%10.1f %10.1f" % (x[i], y[i]))

