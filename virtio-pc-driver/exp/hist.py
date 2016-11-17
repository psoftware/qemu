#!/usr/bin/env python

from matplotlib import pyplot as plt
import argparse
import re


description = "Python script to create histograms"
epilog = "2016 Vincenzo Maffione"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-d', '--data-file',
                       help = "Path to file containing data", action = 'append',
                       default = [])
argparser.add_argument('-o', '--out-file',
                       help = "Path to output PDF file", type = str)
argparser.add_argument('--log-x', action='store_true', help="Logarithmic scale for X")
argparser.add_argument('--log-y', action='store_true', help="Logarithmic scale for Y")
argparser.add_argument('--title', help = "Title", type = str, default="title")
argparser.add_argument('--xlabel', help = "Title", type = str, default="xlabel")
argparser.add_argument('--ylabel', help = "Title", type = str, default="ylabel")
argparser.add_argument('--legend-loc', type = str,
                       help = "Location of the legend", default = 'upper left')
argparser.add_argument('-i', '--interactive', action='store_true', help="Interactive mode")
argparser.add_argument('-c', '--cumulative', action='store_true', help="Cumulative mode")
argparser.add_argument('-x', '--cutoff', type = int, help="Cut off value")
argparser.add_argument('-s', '--scale', type = float, help="Scale value", default=1.0)

args = argparser.parse_args()

xs = []

for data_file in args.data_file:
    x = []
    fin = open(data_file)
    while 1:
        line = fin.readline()
        if line == '':
            break

        if line.startswith('#'):
            continue

        m = re.match('\d+', line)
        if m == None:
            continue

        val = int(m.group(0)) * args.scale
        if args.cutoff != None and val > args.cutoff:
            continue

        x.append(val)
    fin.close()
    xs.append(x)

#Plotting to our canvas
for x in xs:
    if args.cumulative:
        plt.hist(x, bins = 100, cumulative=True, histtype='step', normed=1)
    else:
        plt.hist(x, bins = 100, normed=1)

#plt.axis([0, 10, 0, 10]) # [xmin, xmax, ymin, ymax]
plt.ylabel(args.ylabel)
plt.xlabel(args.xlabel)
plt.title(args.title)
plt.grid(True)
plt.legend(loc=args.legend_loc)

if args.log_x:
    plt.xscale('log')
if args.log_y:
    plt.yscale('log')

#Saving what we plotted
if args.out_file:
    plt.savefig(args.out_file)

if args.interactive:
    plt.show()
