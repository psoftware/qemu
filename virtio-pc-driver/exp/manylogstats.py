#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math


def b_model(Wp, Wc, Sp, Sc):
    if Wp == Wc:
        return 0
    if Wp < Wc:
        return math.floor(Sp/(Wc-Wp)) + 1
    return math.floor(Sc/(Wp-Wc)) + 1

def T_model(Wp, Wc, Sp, Sc, Np, Nc):
    if Wp == Wc:
        return Wp
    b = b_model(Wp, Wc, Sp, Sc)
    if Wp < Wc:
        return Wc + Nc/b
    return Wp + Np/b

def T_batch(Wp, Wc, Np, Nc, b):
    if b <= 0:
        return max(Wp, Wc)

    if Wp < Wc:
        return Wc + Nc/b
    return Wp + Np/b


def load_producer_stats(args, x):
    x['np'] = dict()
    x['wp'] = dict()
    fin = open(args.np_from_file)
    first = True

    while 1:
        line = fin.readline()
        if line == '':
            break

        m = re.search(r'virtpc: set Wp=(\d+)ns', line)
        if m != None:
            w = int(m.group(1))
            x['np'][w] = []
            first = True

            continue

        m = re.search(r'(\d+) np (\d+) wp', line)
        if m == None:
            continue

        if first:
            first = False
            continue

        x['np'][w].append(int(m.group(1)))
        x['wp'][w].append(int(m.group(2)))
    fin.close()


## N.B. This currently assumes a variable Wp and a fixed Wc

description = "Python script to compute mean and standard deviation"
epilog = "2016 Vincenzo Maffione"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-d', '--data-file',
                       help = "Path to file containing data", type=str,
                       required = True)
argparser.add_argument('--sc',
                       help = "sc", type=int,
                       default = 800)
argparser.add_argument('--np',
                       help = "np", type=int,
                       default = 1080)
argparser.add_argument('--sp',
                       help = "sc", type=int,
                       default = 7600)
argparser.add_argument('--nc',
                       help = "np", type=int,
                       default = 800)
argparser.add_argument('--np-from-file',
                       help = "log file to extract np", type=str)

args = argparser.parse_args()

x = dict()

x['items'] = dict()
x['kicks'] = dict()
x['spkicks'] = dict()
x['sleeps'] = dict()
x['intrs'] = dict()
x['latency'] = dict()
x['wc'] = dict()

if args.np_from_file:
    load_producer_stats(args, x)

first = False

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
        x['spkicks'][w] = []
        x['sleeps'][w] = []
        x['intrs'][w] = []
        x['latency'][w] = []
        x['wc'][w] = []
        first = True

        continue

    m = re.search(r'(\d+) items/s (\d+) kicks/s (\d+) sleeps/s (\d+) intrs/s (\d+) latency(?: (\d+) spkicks/s (\d+) wc)?', line)
    if m == None:
        continue

    if first:
        first = False
        continue

    x['items'][w].append(int(m.group(1)))
    x['kicks'][w].append(int(m.group(2)))
    x['sleeps'][w].append(int(m.group(3)))
    x['intrs'][w].append(int(m.group(4)))
    x['latency'][w].append(int(m.group(5)))
    if m.group(6):
        x['spkicks'][w].append(int(m.group(6)))
    else:
        x['spkicks'][w].append(0)
    if m.group(7):
        x['wc'][w].append(int(m.group(7)))
    else:
        x['wc'][w].append(0)

fin.close()

print("%10s %10s %10s %10s %10s %10s %10s %10s %10s %10s %10s %10s %10s" % ('var', 'Tavg', 'Tmodel', 'Tbatch', 'batch', 'Bmodel', 'items', 'kicks', 'spkicks', 'csleeps', 'intrs', 'latency', 'Np'))
for w in sorted(x['items']):
    if len(x['items'][w]) == 0:
        print("Warning: no samples for w=%d" % (w,))
        continue

    wmin = numpy.mean(x['wc'][w])

    denom = max(numpy.mean(x['kicks'][w]), numpy.mean(x['sleeps'][w]), numpy.mean(x['intrs'][w]))
    b_meas = numpy.mean(x['items'][w])/denom # not taking into account spurious kicks
    denom = max(numpy.mean(x['kicks'][w]) + numpy.mean(x['spkicks'][w]), numpy.mean(x['sleeps'][w]), numpy.mean(x['intrs'][w]))
    b_meas_spurious = numpy.mean(x['items'][w])/denom # taking into account spurious kicks

    sc = args.sc
    if args.sc < 0:
        sc = numpy.mean(x['latency'][w])

    wx = w

    if args.np_from_file:
        # handle quantization error
        if w in x['np']:
            np = numpy.mean(x['np'][w])
            wx = numpy.mean(x['wp'][w])
        elif w+1 in x['np']:
            np = numpy.mean(x['np'][w+1])
            wx = numpy.mean(x['wp'][w+1])
        elif w-1 in x['np']:
            np = numpy.mean(x['np'][w-1])
            wx = numpy.mean(x['wp'][w-1])
        else:
            print("Default to Np=%d for w=%d", args.np, w)
            np = args.np
    else:
        np = args.np

    print("%10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f %10.1f" % (wx,
                                    1000000000/numpy.mean(x['items'][w]),
                                    T_model(wx, wmin, args.sp, sc, np, args.nc),
                                    T_batch(wx, wmin, np, args.nc, b_meas_spurious),
                                    b_meas,
                                    b_model(wx, wmin, args.sp, sc),
                                    numpy.mean(x['items'][w]),
                                    numpy.mean(x['kicks'][w]),
                                    numpy.mean(x['spkicks'][w]),
                                    numpy.mean(x['sleeps'][w]),
                                    numpy.mean(x['intrs'][w]),
                                    numpy.mean(x['latency'][w]),
                                    np))
