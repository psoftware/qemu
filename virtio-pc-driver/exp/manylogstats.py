#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math


def T_model(Wp, Wc, Sc, Np):
    if Wp == Wc:
        return Wp
    b = math.floor(Sc/(Wp-Wc)) + 1
    return Wp + Np/b


## N.B. This currently assumes a variable Wp and a fixed Wc

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


fin = open(args.data_file)
while 1:
    line = fin.readline()
    if line == '':
        break

    m = re.search(r'virtpc: set Wp=(\d+)ns', line)
    if m != None:
        w = int(m.group(1))
        x['items'][w] = []
        x['kicks'][w] = []
        x['sleeps'][w] = []
        x['intrs'][w] = []
        x['latency'][w] = []

        continue

    m = re.search(r'(\d+) items/s (\d+) kicks/s (\d+) sleeps/s (\d+) intrs/s (\d+) latency', line)
    if m == None:
        continue

    x['items'][w].append(int(m.group(1)))
    x['kicks'][w].append(int(m.group(2)))
    x['sleeps'][w].append(int(m.group(3)))
    x['intrs'][w].append(int(m.group(4)))
    x['latency'][w].append(int(m.group(5)))

fin.close()

wmin = min([w for w in x['items']])

print("%10s %10s %10s %10s %10s %10s %10s %10s %10s" % ('var', 'items', 'Tavg', 'Tmodel', 'kicks', 'csleeps', 'intrs', 'batch', 'latency'))
for w in sorted(x['items']):
    denom = max(numpy.mean(x['kicks'][w]), numpy.mean(x['sleeps'][w]), numpy.mean(x['intrs'][w]))
    print("%10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f" % (w, numpy.mean(x['items'][w]),
                                    1000000000/numpy.mean(x['items'][w]),
                                    T_model(w, wmin, 650, 1080),
                                    numpy.mean(x['kicks'][w]),
                                    numpy.mean(x['sleeps'][w]),
                                    numpy.mean(x['intrs'][w]),
                                    numpy.mean(x['items'][w])/denom,
                                    numpy.mean(x['latency'][w])))
