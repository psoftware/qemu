#!/usr/bin/env python

import re
import sys
import argparse
import numpy
import math


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

args = argparser.parse_args()

tsc_offset = int(open(args.directory + '/o').read().strip())
print("tsc offset is %d" % (tsc_offset,))

h = {'ts': [], 'id': [], 'type': []}
g = {'ts': [], 'id': [], 'type': []}
m = {'ts': [], 'id': [], 'type': []}

trace_load('h', h, 0)
trace_load('g', g, tsc_offset)

h_i = 0
g_i = 0
h_max = len(h['ts'])
g_max = len(g['ts'])

t_last = 0
p_first = 0

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

    if t_last == 0:
        t_last = m['ts'][-1]
        m['ts'][-1] = 0
    else:
        nxt = m['ts'][-1]
        m['ts'][-1] -= t_last
        t_last = nxt

    if p_first == 0:
        p_first = m['id'][-1]
        m['id'][-1] = 0
    else:
        m['id'][-1] -= p_first

descr = dict()
descr[1] = 'P pub'
descr[2] = 'C see'
descr[3] = 'P restart'
descr[4] = 'C restart'

for i in range(len(m['ts'])):
    print("%6d: #%6d %-6s" % (m['ts'][i]*10/35, m['id'][i], descr[m['type'][i]]))

