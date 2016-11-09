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
argparser.add_argument('-t', '--num-trials',
                       help = "Number of samples for each point", type=int,
                       default = 10)

args = argparser.parse_args()

x = dict()

x['items'] = dict()
x['kicks'] = dict()
x['sleeps'] = dict()
x['intrs'] = dict()
x['latency'] = dict()

w = [math.floor(150*pow(1.0555, z)) for z in range(0,99)]
wi = -1

parseh = False

fin = open(args.data_file)
while 1:
    line = fin.readline()
    if line == '':
        break

    m = re.search(r'virtpc: set', line)
    if m != None:
        if not parseh:
            parseh = True
            wi += 1
            x['items'][w[wi]] = []
            x['kicks'][w[wi]] = []
            x['sleeps'][w[wi]] = []
            x['intrs'][w[wi]] = []
            x['latency'][w[wi]] = []
        continue

    m = re.search(r'(\d+) items/s (\d+) kicks/s (\d+) sleeps/s (\d+) intrs/s (\d+) latency', line)
    if m == None:
        continue

    parseh = False

    x['items'][w[wi]].append(int(m.group(1)))
    x['kicks'][w[wi]].append(int(m.group(2)))
    x['sleeps'][w[wi]].append(int(m.group(3)))
    x['intrs'][w[wi]].append(int(m.group(4)))
    x['latency'][w[wi]].append(int(m.group(5)))

fin.close()

print("%10s %10s %10s %10s %10s %10s" % ('var', 'items', 'kicks', 'csleeps', 'intrs', 'latency'))
for w in sorted(x['items']):
    print("%10.1f %10.1f %10.1f %10.1f %10.1f %10.1f" % (w, numpy.mean(x['items'][w]),
                                    numpy.mean(x['kicks'][w]),
                                    numpy.mean(x['sleeps'][w]),
                                    numpy.mean(x['intrs'][w]),
                                    numpy.mean(x['latency'][w])))
