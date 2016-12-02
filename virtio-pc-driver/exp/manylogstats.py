#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math


def b_model_notif(Wp, Wc, Sp, Sc):
    if Wp == Wc:
        return 0
    if Wp < Wc:
        return math.floor(Sp/(Wc-Wp)) + 1
    return math.floor(Sc/(Wp-Wc)) + 1


def T_model_notif(Wp, Wc, Sp, Sc, Np, Nc):
    if Wp == Wc:
        return Wp
    b = b_model_notif(Wp, Wc, Sp, Sc)
    if Wp < Wc:
        return Wc + Nc/b
    return Wp + Np/b


def T_batch_notif(Wp, Wc, Np, Nc, b):
    if b <= 0:
        return max(Wp, Wc)

    if Wp < Wc:
        return Wc + Nc/b
    return Wp + Np/b


def b_model_sleep(Yc, Yp, Wp, Wc, L):
    if Wp == Wc:
        return 0
    if Wc < Wp:
        # we don't have a model for long sleep, we just
        # pretend Yc saturates at the Yc_MAX
        Yc = min(Yc, (L-1)*Wp - Wc)
        return Yc/(Wp-Wc)
    Yp = min(Yp, (L-1)*Wc - Wp)
    return Yp/(Wc-Wp)


def T_model_sleep(Yc, Yp, Wp, Wc, L):
    return max(Wp, Wc)


def load_producer_stats(args, x):
    x['np'] = dict()
    x['wp'] = dict()
    fin = open(args.p)
    first = True

    while 1:
        line = fin.readline()
        if line == '':
            break

        m = re.search(r'virtpc: set ' + args.varname + '=(\d+)ns', line)
        if m != None:
            v = int(m.group(1))
            x['np'][v] = []
            x['wp'][v] = []
            first = True

            continue

        m = re.search(r'(\d+) np (\d+) wp', line)
        if m == None:
            continue

        if first:
            first = False
            continue

        x['np'][v].append(int(m.group(1)))
        x['wp'][v].append(int(m.group(2)))
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
                       default = -1)
argparser.add_argument('--np',
                       help = "np", type=int,
                       default = 1080)
argparser.add_argument('--sp',
                       help = "sc", type=int,
                       default = 7600)
argparser.add_argument('--nc',
                       help = "np", type=int,
                       default = 800)
argparser.add_argument('-l', '--queue-length',
                       help = "Queue length, used just for sleep tests", type=int,
                       default = 256)
argparser.add_argument('-p',
                       help = "log file to extract np and wp", type=str)
argparser.add_argument('--varname', type=str, default='Wp',
                       help='Name of the variable parameter')

args = argparser.parse_args()

x = dict()

x['items'] = dict()
x['kicks'] = dict()
x['spkicks'] = dict()
x['sleeps'] = dict()
x['intrs'] = dict()
x['latency'] = dict()
x['wc'] = dict()

if args.p:
    load_producer_stats(args, x)

first = False

fin = open(args.data_file)
while 1:
    line = fin.readline()
    if line == '':
        break

    m = re.search(r'virtpc: set ' + args.varname + '=(\d+)ns', line)
    if m != None:
        v = int(m.group(1))
        x['items'][v] = []
        x['kicks'][v] = []
        x['spkicks'][v] = []
        x['sleeps'][v] = []
        x['intrs'][v] = []
        x['latency'][v] = []
        x['wc'][v] = []
        first = True

        continue

    m = re.search(r'(\d+) items/s (\d+) kicks/s (\d+) sleeps/s (\d+) intrs/s (\d+) latency(?: (\d+) spkicks/s (\d+) wc)?', line)
    if m == None:
        continue

    if first:
        first = False
        continue

    x['items'][v].append(int(m.group(1)))
    x['kicks'][v].append(int(m.group(2)))
    x['sleeps'][v].append(int(m.group(3)))
    x['intrs'][v].append(int(m.group(4)))
    x['latency'][v].append(int(m.group(5)))
    if m.group(6):
        x['spkicks'][v].append(int(m.group(6)))
    else:
        x['spkicks'][v].append(0)
    if m.group(7):
        x['wc'][v].append(int(m.group(7)))
    else:
        x['wc'][v].append(0)

fin.close()

print("%9s %9s %9s %9s %9s %9s %7s %7s %9s %9s %9s %9s %9s %9s %9s" % (args.varname + 'n', 'Wp', 'Wc', 'Tavg', 'Tmodel', 'Tbatch', 'batch', 'Bmodel', 'items', 'kicks', 'spkicks', 'csleeps', 'intrs', 'latency', 'Np'))
for v in sorted(x['items']):
    if len(x['items'][v]) == 0:
        print("Warning: no samples for v=%d" % (v,))
        continue

    woth = numpy.mean(x['wc'][v])

    sc = args.sc
    if args.sc < 0:
        sc = numpy.mean(x['latency'][v])

    wx = v

    if args.p:
        # handle quantization error
        if v in x['np']:
            np = numpy.mean(x['np'][v])
            wx = numpy.mean(x['wp'][v])
        elif v+1 in x['np']:
            np = numpy.mean(x['np'][v+1])
            wx = numpy.mean(x['wp'][v+1])
        elif v-1 in x['np']:
            np = numpy.mean(x['np'][v-1])
            wx = numpy.mean(x['wp'][v-1])
        else:
            print("Default to Np=%d for v=%d" %(args.np, v))
            np = args.np
    else:
        np = args.np

    if args.varname in ['Wp', 'Wc']:
        # notification tests
        denom = max(numpy.mean(x['kicks'][v]), numpy.mean(x['intrs'][v]))
        denom_s = max(numpy.mean(x['kicks'][v]) + numpy.mean(x['spkicks'][v]), numpy.mean(x['intrs'][v]))
    else:
        # sleeping tests
        denom = denom_s = numpy.mean(x['sleeps'][v])

    b_meas = numpy.mean(x['items'][v])/denom # not taking into account spurious kicks
    b_meas_spurious = numpy.mean(x['items'][v])/denom_s # taking into account spurious kicks

    if args.varname in ['Wp', 'Wc']:
        # notification tests
        t_model = T_model_notif(wx, woth, args.sp, sc, np, args.nc)
        t_batch = T_batch_notif(wx, woth, np, args.nc, b_meas_spurious)
        b_model = b_model_notif(wx, woth, args.sp, sc)
    else:
        # sleeping tests
        t_model = t_batch = T_model_sleep(v, v, wx, woth, args.queue_length)
        b_model = b_model_sleep(v, v, wx, woth, args.queue_length)

    print("%9.0f %9.0f %9.0f %9.0f %9.0f %9.0f %7.1f %7.1f %9.0f %9.0f %9.0f %9.0f %9.0f %9.0f %9.0f" % (v, wx,
                                    numpy.mean(x['wc'][v]),
                                    1000000000/numpy.mean(x['items'][v]),
                                    t_model,
                                    t_batch,
                                    b_meas,
                                    b_model,
                                    numpy.mean(x['items'][v]),
                                    numpy.mean(x['kicks'][v]),
                                    numpy.mean(x['spkicks'][v]),
                                    numpy.mean(x['sleeps'][v]),
                                    numpy.mean(x['intrs'][v]),
                                    numpy.mean(x['latency'][v]),
                                    np))
