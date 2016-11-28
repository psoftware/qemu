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
            color = 'r'
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
argparser.add_argument('--stdio', action='store_true',
                       help = "Dump merged trace to stdio")
argparser.add_argument('--stdio-producer', action='store_true',
                       help = "Dump producer trace to stdio")
argparser.add_argument('--stdio-consumer', action='store_true',
                       help = "Dump consumer trace to stdio")

args = argparser.parse_args()

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
    if ts_start > 0:
        if g['type'][g_i] == 1: # PKPUB
            p_events.append((ts_start, g['id'][g_i], t_len))
        elif g['type'][g_i] == 3: # NOTIFY DONE
            p_events.append((ts_start, 'n', t_len))

    g_i += 1

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
    if ts_start > 0:
        if h['type'][h_i] == 5: # CSTOPS
            c_events.append((ts_start, h['id'][h_i-1], t_len))
        elif h['type'][h_i] == 2: # PKTSEEN
            if h['type'][h_i-1] == 2:
                c_events.append((ts_start, h['id'][h_i-1], t_len))
            else: # match with a NOTIFY DONE event
                ts_start = -1
                while g_i < g_max and g['ts'][g_i] < h['ts'][h_i]:
                    if g['type'][g_i] == 3:
                        ts_start = g['ts'][g_i]
                    g_i += 1
                if ts_start >= 0:
                    c_events.append((ts_start, 's',
                                     h['ts'][h_i] - ts_start))

    h_i += 1

descr = dict()
descr[1] = 'P pub'
descr[2] = 'C see'
descr[3] = 'P restart'
descr[4] = 'C restart'
descr[5] = 'C stop'

if args.stdio_producer:
    for e in p_events:
        print("%10s %10f" % (e[1], e[2]))
    quit()

if args.stdio_consumer:
    for e in c_events:
        print("%10s %10f" % (e[1], e[2]))
    quit()

if args.stdio:
    # Merge
    h_i = 0
    g_i = 0
    while h_i < h_max or g_i < g_max:

        if g_i >= g_max or (h_i < h_max and h['ts'][h_i] < g['ts'][g_i]):
            m['ts'].append(h['ts'][h_i])
            m['id'].append(h['id'][h_i])
            m['type'].append(h['type'][h_i])
            h_i += 1
        else:
            m['ts'].append(g['ts'][g_i])
            m['id'].append(g['id'][g_i])
            m['type'].append(g['type'][g_i])
            g_i += 1

    for i in range(len(m['ts'])):
        print("%6d: #%6d %-6s" % (m['ts'][i]*10/35, m['id'][i], descr[m['type'][i]]))

    quit()

dump(p_events, c_events)

