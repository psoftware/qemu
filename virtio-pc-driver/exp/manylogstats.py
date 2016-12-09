#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math


def b_model_notif(Wp, Wc, Sp, Sc, L):
    if Wp == Wc:
        return 0
    if Wp < Wc:
        kC = L * 3/4
        return math.floor((Sp + (kC-1) * Wp)/(Wc-Wp)) + kC
    return math.floor(Sc/(Wp-Wc)) + 1


def T_model_notif(Wp, Wc, Sp, Sc, Np, Nc, L):
    if Wp == Wc:
        return Wp
    b = b_model_notif(Wp, Wc, Sp, Sc, L)
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
    x['yp'] = dict()
    x['psleeps'] = dict()
    fin = open(args.guest_log)
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
            x['yp'][v] = []
            x['psleeps'][v] = []
            first = True

            continue

        m = re.search(r'(\d+) np (\d+) wp(?: (\d+) yp (\d+) sleeps/s)', line)
        if m == None:
            continue

        if first:
            first = False
            continue

        x['np'][v].append(int(m.group(1)))
        x['wp'][v].append(int(m.group(2)))
        if m.group(3):
            x['yp'][v].append(int(m.group(3)))
            x['psleeps'][v].append(int(m.group(4)))
        else:
            x['yp'][v].append(0)
            x['psleeps'][v].append(0)
    fin.close()


## N.B. This currently assumes a variable Wp and a fixed Wc

description = "Python script to compute mean and standard deviation"
epilog = "2016 Vincenzo Maffione"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-H', '--host-log',
                       help = "host log file", type=str,
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
argparser.add_argument('-G', '--guest-log',
                       help = "guest log file to extract np and wp", type=str)
argparser.add_argument('--varname', type=str, default='Wp',
                       help='Name of the variable parameter')

args = argparser.parse_args()

x = dict()

x['items'] = dict()
x['kicks'] = dict()
x['spkicks'] = dict()
x['sleeps'] = dict()
x['intrs'] = dict()
x['sc'] = dict()
x['wc'] = dict()
x['nc'] = dict()
x['latency'] = dict()
x['yc'] = dict()

if args.guest_log:
    load_producer_stats(args, x)

first = False

fin = open(args.host_log)
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
        x['sc'][v] = []
        x['wc'][v] = []
        x['nc'][v] = []
        x['latency'][v] = []
        x['yc'][v] = []
        first = True

        continue

    m = re.search(r'(\d+) items/s (\d+) kicks/s (\d+) sleeps/s (\d+) intrs/s (\d+) sc (\d+) spkicks/s (\d+) wc (\d+) nc (\d+) latency (\d+) yc', line)
    if m == None:
        continue

    if first:
        first = False
        continue

    x['items'][v].append(int(m.group(1)))
    x['kicks'][v].append(int(m.group(2)))
    x['sleeps'][v].append(int(m.group(3)))
    x['intrs'][v].append(int(m.group(4)))
    x['sc'][v].append(int(m.group(5)))
    x['spkicks'][v].append(int(m.group(6)))
    x['wc'][v].append(int(m.group(7)))
    x['nc'][v].append(int(m.group(8)))
    x['latency'][v].append(int(m.group(9)))
    x['yc'][v].append(int(m.group(10)))

fin.close()

print("%7s %7s %7s %9s %9s %9s %7s %7s %9s %9s %9s %9s %9s %7s %7s %9s %8s" % (args.varname + 'n', 'Wp', 'Wc', 'Tavg', 'Tmodel', 'Tbatch', 'batch', 'Bmodel', 'items', 'kicks', 'spkicks', 'csleeps', 'intrs', 'Sc', 'Np', 'latency', 'Yc'))

for v in sorted(x['items']):
    if len(x['items'][v]) == 0:
        print("Warning: no samples for v=%d" % (v,))
        continue

    woth = numpy.mean(x['wc'][v])

    sc = args.sc
    if args.sc < 0:
        sc = numpy.mean(x['sc'][v])

    wx = v

    if args.guest_log:
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

    yc = numpy.mean(x['yc'][v])

    if args.varname in ['Wp', 'Wc']:
        # notification tests
        t_model = T_model_notif(wx, woth, args.sp, sc, np, args.nc, args.queue_length)
        t_batch = T_batch_notif(wx, woth, np, args.nc, b_meas_spurious)
        b_model = b_model_notif(wx, woth, args.sp, sc, args.queue_length)
    else:
        # sleeping tests
        t_model = t_batch = T_model_sleep(yc, yc, wx, woth, args.queue_length)
        b_model = b_model_sleep(yc, yc, wx, woth, args.queue_length)

    print("%7.0f %7.0f %7.0f %9.0f %9.0f %9.0f %7.1f %7.1f %9.0f %9.0f %9.0f %9.0f %9.0f %7.0f %7.0f %9.0f %8.0f" % (v, wx,
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
                                    numpy.mean(x['sc'][v]),
                                    np,
                                    numpy.mean(x['latency'][v]),
                                    yc))
