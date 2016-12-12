#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math
from matplotlib import pyplot as plt


def dump(prod_events, cons_events):
    from matplotlib import pyplot as plt

    xunit = 2000
    xunits = 180

    fig = plt.figure()
    ax = plt.axes(xlim=(0, xunits * xunit), ylim=(0, 100))

    y = 95
    ofs = 0
    size = 2
    for ev in prod_events:
        if ev[0] + ev[2] - ofs > xunits * xunit:
            ofs += xunits * xunit
            y -= 10
            if y < 0:
                break
        ev = (ev[0] - ofs, ev[1], ev[2])
        if ev[1] == 'z':
            line = plt.Line2D((ev[0], ev[0] + ev[2]), (y + size/2, y + size/2), lw=4.5)
            plt.gca().add_line(line)
        elif ev[1] == 'n':
            poly = plt.Polygon([[ev[0], y], [ev[0], y + size], [ev[0] + ev[2], y]], color = 'y')
            plt.gca().add_patch(poly)
        elif ev[1] == 's':
            poly = plt.Polygon([[ev[0], y], [ev[0] + ev[2], y], [ev[0] + ev[2], y + size]], color = '#0080f0')
            plt.gca().add_patch(poly)
        else:
            color = 'g'
            rectangle = plt.Rectangle((ev[0], y), ev[2], size, fc=color)
            plt.gca().add_patch(rectangle)

    y = 92
    ofs = 0
    for ev in cons_events:
        if ev[0] + ev[2] - ofs > xunits * xunit:
            ofs += xunits * xunit
            y -= 10
            if y < 0:
                break
        ev = (ev[0] - ofs, ev[1], ev[2])
        if ev[1] == 'z':
            line = plt.Line2D((ev[0], ev[0] + ev[2]), (y + size/2, y + size/2), lw=4.5)
            plt.gca().add_line(line)
        elif ev[1] == 'n':
            poly = plt.Polygon([[ev[0], y], [ev[0], y + size], [ev[0] + ev[2], y + size]], color = 'y')
            plt.gca().add_patch(poly)
        elif ev[1] == 's':
            poly = plt.Polygon([[ev[0], y + size], [ev[0] + ev[2], y + size], [ev[0] + ev[2], y]], color = '#0080f0')
            plt.gca().add_patch(poly)
        else:
            color = 'k' if ev[1] == 'd' else 'r'
            rectangle = plt.Rectangle((ev[0], y), ev[2], size, fc=color)
            plt.gca().add_patch(rectangle)

    plt.show()


def trace_load(name, d, ofs):
    fin = open(args.directory + '/' + name)

    while 1:
        line = fin.readline()
        if line == '':
            break

        m = re.search(r': (\d+) (\d+) (\d+)', line)
        if m != None:
            d['ts'].append(int(m.group(1)) - ofs)
            d['id'].append(int(m.group(2)))
            d['type'].append(int(m.group(3)))
            continue

    fin.close()


description = "Python script to trace prodcons"
epilog = "2016 Vincenzo Maffione"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-d', '--directory',
                       help = "Directory to traces", type=str,
                       required = True)
argparser.add_argument('--stdio-producer', action='store_true',
                       help = "Dump producer trace to stdio")
argparser.add_argument('--stdio-consumer', action='store_true',
                       help = "Dump consumer trace to stdio")
argparser.add_argument('--skip',
                       help = "Skip percentage of events", type=int, default = 0)

args = argparser.parse_args()


descr = dict()
descr[1] = 'P pub'
descr[2] = 'C see'
descr[3] = 'P restart'
descr[4] = 'C restart'
descr[5] = 'C stop'

tsc_offset = int(open(args.directory + '/o').read().strip())
print("tsc offset is %d" % (tsc_offset,))

h = {'ts': [], 'id': [], 'type': []}
g = {'ts': [], 'id': [], 'type': []}
m = {'ts': [], 'id': [], 'type': []}

trace_load('h', h, 0)
trace_load('g', g, tsc_offset)

h_max = len(h['ts'])
g_max = len(g['ts'])

p_t = 0
c_t = 0
p_events = []
c_events = []

nps = []
wps = []
scs = []
wcs = []

# Compute normalization offsets
t_first = max(g['ts'][0], h['ts'][0])
pkt_first = min(g['id'][0], h['id'][0])

print("First ts: %d, first pkt: %d" % (t_first, pkt_first))

# Build producer events
g_i = 1
g['ts'][0] -= t_first
g['id'][0] -= pkt_first
while g_i < g_max:
    g['ts'][g_i] = (g['ts'][g_i] - t_first) * 10 / 35

    ts_start = g['ts'][g_i-1]
    t_len = g['ts'][g_i] - g['ts'][g_i-1]

    g['id'][g_i] -= pkt_first
    if ts_start > 0 and t_len > 0:
        if g['type'][g_i] == 1: # PKPUB
            p_events.append((ts_start, g['id'][g_i], t_len))
            wps.append(t_len)
        elif g['type'][g_i] == 3: # NOTIFY DONE
            p_events.append((ts_start, 'n', t_len))
            nps.append(t_len)

    g_i += 1

deltas = []

# Build consumer events
h_i = 1
h['ts'][0] -= t_first
h['id'][0] -= pkt_first
g_i = 0
while h_i < h_max:
    h['ts'][h_i] = (h['ts'][h_i] - t_first) * 10 / 35

    ts_start = h['ts'][h_i-1]
    t_len = h['ts'][h_i] - h['ts'][h_i-1]

    h['id'][h_i] -= pkt_first
    if ts_start > 0 and t_len > 0:
        if h['type'][h_i] == 5: # CSTOPS
            if h['type'][h_i-1] == 2:
                c_events.append((ts_start, h['id'][h_i-1], t_len))
                wcs.append(t_len)
            else: # double CSTOPS --> dry run
                c_events.append((ts_start, 'd', t_len))

        elif h['type'][h_i] == 2: # PKTSEEN
            if h['type'][h_i-1] == 2:
                c_events.append((ts_start, h['id'][h_i-1], t_len))
                wcs.append(t_len)
            else: # match with a NOTIFY DONE event
                ts_start = -1
                n_start = -1
                while g_i < g_max and g['ts'][g_i] < h['ts'][h_i]:
                    if g_i > 0 and g['type'][g_i] == 3:
                        n_start = g['ts'][g_i-1]
                        ts_start = g['ts'][g_i]
                    g_i += 1
                t_len = h['ts'][h_i] - ts_start
                if ts_start >= 0 and t_len > 0:
                    c_events.append((ts_start, 's', t_len))
                    scs.append(t_len)
                    if len(c_events) >= 2:
                        deltas.append((n_start - (c_events[-2][0] + c_events[-2][2]),
                                       c_events[-1][2]))

    h_i += 1

#for d in deltas:
#    print("%6.0f %6.0f" % d)
#quit()

if args.skip > 0 and args.skip < 95:
    numc = nump = int(min(len(c_events), len(p_events)) * args.skip / 100)
    while nump > 0 and numc > 0:
        if c_events[0][0] < p_events[0][0]:
            c_events.pop(0)
            numc -= 1
        else:
            p_events.pop(0)
            nump -= 1
    t_first = max(p_events[0][0], c_events[0][0])
    c_events_new = []
    for e in c_events:
        c_events_new.append((e[0] - t_first, e[1], e[2]))
    c_events = c_events_new
    p_events_new = []
    for e in p_events:
        p_events_new.append((e[0] - t_first, e[1], e[2]))
    p_events = p_events_new


print("averages: Wc %5.1f+/-%5.2f Sc %5.1f+/-%5.2f Wp %5.1f+/-%5.2f Np %5.1f+/-%5.2f" % (
                numpy.mean(wcs), numpy.std(wcs), numpy.mean(scs), numpy.std(scs),
                numpy.mean(wps), numpy.std(wps), numpy.mean(nps), numpy.std(nps)))

# compute consumer batches
if False:
    bs = []
    bcur = 0
    for e in c_events:
        if e[1] == 's' or e[1] == 'd':
            if bcur:
                bs.append(bcur)
                print(bcur)
                bcur = 0
        else:
            bcur += 1
    quit()

if args.stdio_producer:
    for e in p_events:
        print("%10s %10.0f" % (e[1], e[2]))
    quit()

if args.stdio_consumer:
    for e in c_events:
        print("%10s %10.0f" % (e[1], e[2]))
    quit()

dump(p_events, c_events)

