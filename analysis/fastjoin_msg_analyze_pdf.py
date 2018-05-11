#! /usr/bin/python2

import argparse
import copy
import datetime
import dpkt
import fnmatch
import os
import psycopg2
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
import matplotlib.pyplot as plt
import numpy as np
import shutil
import socket
import subprocess
import sys


parser = argparse.ArgumentParser(description="Produce plots for wget scenarios")
parser.add_argument("results_dir", help="Directory where test results are located")
parser.add_argument("output_dir", help="Directory where graphs will be produced")

args = parser.parse_args()

PATHS = "paths"
NETEM = "netem"


class cd:

    """ Context manager to change the current working directory """

    def __init__(self, newPath):
        self.newPath = newPath

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


def check_directory_exists(directory):
    if os.path.exists(directory):
        if not os.path.isdir(directory):
            print(directory + " is a file")
            sys.exit(1)
    else:
        os.makedirs(directory)


def extractTcpTimeFromTrace(tracePath):
    cmd = ["tstat", "-s", "results", tracePath]
    devnull = open(os.devnull, 'w')
    if subprocess.call(cmd, stdout=devnull) != 0:
        print("Error of tstat for", tracePath)
        return None

    devnull.close()
    duration = None
    with cd("results"):
        with cd(os.listdir('.')[0]):
            resultsFile = open("log_tcp_complete", "r")
            for line in resultsFile.readlines():
                # Case 1: line start with #; skip it
                if not line.startswith("#"):
                    duration = float(line.split()[30]) / 1000.0
                    break

    shutil.rmtree("results")

    resultsFile.close()
    return duration


def getSiriDelays(logPath):
    logFile = open(logPath)
    lines = logFile.readlines()
    delays = []
    for line in lines:
        try:
            delays.append(int(float(line) * 1000.0))
        except ValueError:
            pass

    logFile.close()
    return delays


def extractMptcpTimeFromTrace(tracePath):
    """ mptcptrace is not aware of MP_FAST_JOIN_IN yet, so don't use it """
    pcapFile = open(tracePath)
    pcap = dpkt.pcap.Reader(pcapFile)
    synTime = None
    synAckTime = None
    startCell = None
    ipFirst = None
    ipCell = None
    firstDataCell = None
    lastDataCell = None
    bytesFirst = 0
    bytesCell = 0
    percCell = 0.0
    endTime = None
    rstTime = None
    finTime = None
    try:
        for ts, buf in pcap:
            if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                eth = dpkt.sll.SLL(buf)
            else:
                eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) == dpkt.ip.IP or type(eth.data) == dpkt.ip6.IP6:
                ip = eth.data
                if type(ip.data) == dpkt.tcp.TCP:
                    tcp = ip.data
                    synFlag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                    ackFlag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
                    finFlag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                    rstFlag = (tcp.flags & dpkt.tcp.TH_RST) != 0

                    # Try to catch the last packet
                    endTime = datetime.timedelta(seconds=ts)

                    if synFlag and synTime is None:
                        synTime = datetime.timedelta(seconds=ts)
                        ipFirst = ip.src

                    elif synFlag and not ackFlag and (synAckTime is not None) and ip.src != ipFirst:
                        startCell = datetime.timedelta(seconds=ts)
                        ipCell = ip.src

                    elif (synFlag and ackFlag):
                        synAckTime = datetime.timedelta(seconds=ts)

                    elif finFlag and not finTime:
                        finTime = datetime.timedelta(seconds=ts)
                    elif rstFlag:
                        rstTime = datetime.timedelta(seconds=ts)
                    elif tcp.data:
                        #print(socket.inet_ntoa(ip.dst))
                        if ip.dst == ipCell or ip.src == ipCell:
                            bytesCell += ip.len - tcp.off * 4 - ip.hl * 4
                            lastDataCell = datetime.timedelta(seconds=ts)
                            if not firstDataCell:
                                firstDataCell = datetime.timedelta(seconds=ts)
                        else:
                            bytesFirst += ip.len - tcp.off*4 - ip.hl * 4

    except dpkt.dpkt.NeedData:
        print("Trace with missing data " + tracePath)
        return None

    if finTime:
        endTime = finTime
    elif rstTime:
        endTime = rstTime

    pcapFile.close()
    if synTime is None or synAckTime is None:
        print("No data for", tracePath)
        return None

    if firstDataCell:
        timeUsedCell = 100.0 * (lastDataCell - firstDataCell).total_seconds() / (endTime - synTime).total_seconds()
    else:
        timeUsedCell = 0.0

    if startCell:
        startCell = 100.0 - 100.0 * ((startCell - synTime).total_seconds() / (endTime - synTime).total_seconds())
    else:
        startCell = 0.0

    if bytesFirst + bytesCell > 0:
        percCell = bytesCell * 100.0 / (bytesCell + bytesFirst)

    return (endTime - synTime).total_seconds(), percCell, timeUsedCell, startCell


def getSimpleValuesInCc(valuesCc, dirpath, filenames, timeInLabel=True):
    for filename in filenames:
        #if filename == "https_client.log":
        if filename.endswith("_client.pcap"):
            # wgetTime = extractTimeFromClientLog(os.path.join(dirpath, filename))
            wgetTime = None
            if "_mptcp_" in filename:
                wgetTime, percCell, timeUsedCell, startCell = extractMptcpTimeFromTrace(os.path.join(dirpath, filename))
                delays = [max(getSiriDelays(os.path.join(dirpath, "msg_client.log")))]
            elif "_tcp_" in filename:
                wgetTime = extractTcpTimeFromTrace(os.path.join(dirpath, filename))
            if wgetTime is None:
                return
            dirpathSplit = dirpath.split("/")
            directory = dirpathSplit[-7]
            configInfo = dirpathSplit[-6]
            if timeInLabel:
                valuesCc.append({"value": (delays, percCell, timeUsedCell, startCell), "label": configInfo + ": " + str(wgetTime) + "s", "directory": directory})
            else:
                valuesCc.append({"value": (delays, percCell, timeUsedCell, startCell), "label": configInfo, "directory": directory})


def getSimpleTcpAndMptcpValues(results_directory="results", timeInLabel=True):
    tcpValues = {'reno': {}, 'cubic': {}}
    for directory in os.listdir(results_directory):
        if fnmatch.fnmatch(directory, 'http_*_tcp'):
            for dirpath, dirnames, filenames in os.walk(os.path.join(results_directory, directory)):
                for filename in filenames:
                    #if filename == "https_client.log":
                    if filename.endswith("_client.pcap"):
                        open_bup = dirpath.split("/")[-3]
                        congestion_control = dirpath.split("/")[-1]
                        if open_bup not in tcpValues[congestion_control]:
                            tcpValues[congestion_control][open_bup] = []

                        getSimpleValuesInCc(tcpValues[congestion_control][open_bup], dirpath, filenames, timeInLabel=timeInLabel)

    mptcpValues = {}
    for directory in os.listdir(results_directory):
        print(directory)
        if fnmatch.fnmatch(directory, 'msg_*_mptcp'):
            for dirpath, dirnames, filenames in os.walk(os.path.join(results_directory, directory)):
                for filename in filenames:
                    # if filename == "https_client.log":
                    if filename.endswith("_client.pcap"):
                        topo = dirpath.split("/")[-6]
                        if topo not in mptcpValues:
                            mptcpValues[topo] = {}

                        scheduler = dirpath.split("/")[-5]
                        if scheduler not in mptcpValues[topo]:
                            mptcpValues[topo][scheduler] = {}

                        open_bup = dirpath.split("/")[-4]
                        if open_bup not in mptcpValues[topo][scheduler]:
                            mptcpValues[topo][scheduler][open_bup] = {}

                        use_fastjoin = dirpath.split("/")[-3]
                        if use_fastjoin not in mptcpValues[topo][scheduler][open_bup]:
                            mptcpValues[topo][scheduler][open_bup][use_fastjoin] = {}

                        pkt_bytes = dirpath.split("/")[-2]
                        if pkt_bytes not in mptcpValues[topo][scheduler][open_bup][use_fastjoin]:
                            mptcpValues[topo][scheduler][open_bup][use_fastjoin][pkt_bytes] = {}

                        congestion_control = dirpath.split("/")[-1]
                        if congestion_control not in mptcpValues[topo][scheduler][open_bup][use_fastjoin][pkt_bytes]:
                            mptcpValues[topo][scheduler][open_bup][use_fastjoin][pkt_bytes][congestion_control] = []

                        getSimpleValuesInCc(mptcpValues[topo][scheduler][open_bup][use_fastjoin][pkt_bytes][congestion_control], dirpath, filenames, timeInLabel=timeInLabel)

    return tcpValues, mptcpValues


def boxMatchTcpWithMptcp(tcpValues, mptcpValues):
    tcpPath0Values = []
    tcpPath1Values = []
    tcpPathsValues = {}

    for item in tcpValues:
        # From label, isolate data
        split_config = item["label"].split("_")
        delayBandwidth = split_config[1]
        loss = split_config[-1].split(":")[0]

        for mptcpItem in mptcpValues:
            if mptcpItem["label"] not in tcpPathsValues:
                tcpPathsValues[mptcpItem["label"]] = []
            if "0_" + delayBandwidth in mptcpItem["label"] and "_nt_0_0_loss_" + loss in mptcpItem["label"]:
                tcpPath0Values.append(item)
                tcpPathsValues[mptcpItem["label"]].append(item["value"])
                break
            elif "1_" + delayBandwidth in mptcpItem["label"] and "_nt_1_0_loss_" + loss in mptcpItem["label"]:
                tcpPath1Values.append(item)
                tcpPathsValues[mptcpItem["label"]].append(item["value"])
                break

    return tcpPath0Values, tcpPath1Values, tcpPathsValues


def get_topo_info(topo_str):
    # Hardcoded for 2 paths...
    return_dict = {PATHS: [], NETEM: []}
    split_topo = topo_str.split("_")
    path_0 = split_topo[1]
    path_1 = split_topo[3]
    for path in [path_0, path_1]:
        remaining = path.split("d")[1]
        delay, remaining = remaining.split("qs")
        queuing_delay, bandwidth = remaining.split("b")
        return_dict[PATHS].append({"delay": delay, "queuingDelay": queuing_delay, "bandwidth": bandwidth})

    netem_0 = split_topo[8]
    netem_1 = split_topo[13]
    for netem in [netem_0, netem_1]:
        return_dict[NETEM].append(netem)

    return return_dict


# function for setting the colors of the box plots pairs
def setBoxColors(bp):
    plt.setp(bp['boxes'][0], color="#bdbdbd", linewidth=2)
    plt.setp(bp['caps'][0], color="#bdbdbd", linewidth=2)
    plt.setp(bp['caps'][1], color="#bdbdbd", linewidth=2)
    plt.setp(bp['whiskers'][0], color="#bdbdbd", linewidth=2)
    plt.setp(bp['whiskers'][1], color="#bdbdbd", linewidth=2)
    plt.setp(bp['fliers'][0], color="#bdbdbd", linewidth=2)
    plt.setp(bp['fliers'][1], color="#bdbdbd", linewidth=2)
    plt.setp(bp['medians'][0], color="#bdbdbd", linewidth=2)

    plt.setp(bp['boxes'][1], color='#636363', linewidth=2)
    plt.setp(bp['caps'][2], color='#636363', linewidth=2)
    plt.setp(bp['caps'][3], color='#636363', linewidth=2)
    plt.setp(bp['whiskers'][2], color='#636363', linewidth=2)
    plt.setp(bp['whiskers'][3], color='#636363', linewidth=2)
    # plt.setp(bp['fliers'][2], color='red')
    # plt.setp(bp['fliers'][3], color='red')
    plt.setp(bp['medians'][1], color='#636363', linewidth=2)

    # plt.setp(bp['boxes'][2], color='#998ec3', linewidth=2)
    # plt.setp(bp['caps'][4], color='#998ec3', linewidth=2)
    # plt.setp(bp['caps'][5], color='#998ec3', linewidth=2)
    # plt.setp(bp['whiskers'][4], color='#998ec3', linewidth=2)
    # plt.setp(bp['whiskers'][5], color='#998ec3', linewidth=2)
    # # plt.setp(bp['fliers'][2], color='red')
    # # plt.setp(bp['fliers'][3], color='red')
    # plt.setp(bp['medians'][2], color='#998ec3', linewidth=2)


def boxPlot(mptcpValues, output):
    text = {("default-1_server", "0", "0"): "Normal",
            # ("default-1_server", "0", "1"): "Oracle with Fast Join",
            ("default-1_server", "0", "1"): "Fast Join"}
    results = {}

    for topo in mptcpValues:
        # First collect all results, then plot them
        delays = []
        percCell = []
        timeUsed = []
        startCell = []
        labels = []
        results[topo] = {}
        for config in [("default-1_server", "0", "0"), ("default-1_server", "0", "1")]:
            labels.append(text[config])
            delay = []
            perc = []
            used = []
            start = []
            for item in mptcpValues[topo][config[0]][config[1]][config[2]]["olia"]:
                delay += item["value"][0]
                perc.append(item["value"][1])
                used.append(item["value"][2])
                start.append(item["value"][3])

            delays.append(delay)
            percCell.append(perc)
            timeUsed.append(used)
            startCell.append(start)

        # Now perform the four graphes
        plt.figure()
        plt.clf()
        plt.boxplot(delays, labels=labels)
        plt.title("Delay Request-Response [ms]")
        plt.savefig(os.path.join(output, 'delays_' + topo + '.pdf'))
        plt.close('all')
        results[topo]["delays"] = delays

        plt.figure()
        plt.clf()
        plt.boxplot(percCell, labels=labels)
        plt.title("Percentage on cellular")
        plt.savefig(os.path.join(output, 'perc_cell_' + topo + '.pdf'))
        plt.close('all')
        results[topo]["percCell"] = percCell

        plt.figure()
        plt.clf()
        plt.boxplot(timeUsed, labels=labels)
        plt.title("Percentage time cellular used")
        plt.savefig(os.path.join(output, 'time_used_' + topo + '.pdf'))
        plt.close('all')
        results[topo]["timeUsed"] = timeUsed

        plt.figure()
        plt.clf()
        plt.boxplot(startCell, labels=labels)
        plt.title("Percentage time cellular on")
        plt.savefig(os.path.join(output, 'start_cell_' + topo + '.pdf'))
        plt.close('all')
        results[topo]["startCell"] = startCell

    plt.figure(figsize=(15, 5.5))
    plt.clf()
    ax = plt.axes()
    plt.hold(True)
    # bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%"]["delays"], positions=[1, 2], widths=0.6)
    # setBoxColors(bp)
    # plt.title('Delay Request-Response [ms]')
    plt.ylabel('Max Delay [ms]', fontsize=28)
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%"]["delays"])#, positions=[4, 5], widths=0.6)
    setBoxColors(bp)
    # plt.xlim(0, 5)
    plt.ylim(650, 800)
    plt.tick_params(
    axis='x',          # changes apply to the x-axis
    which='both',      # both major and minor ticks are affected
    bottom='off',      # ticks along the bottom edge are off
    top='off',         # ticks along the top edge are off
    labelbottom='off') # labels along the bottom edge are off
    # ax.set_xticklabels(['No loss', 'Loosing primary subflow'])
    # ax.set_xticks([1.5, 4.5])
    # draw temporary red and blue lines and use them to create a legend
    hB, = plt.plot([1, 1], color="#bdbdbd", linewidth=2)
    hR, = plt.plot([1, 1], color="#636363", linewidth=2)
    # hL, = plt.plot([1, 1], color="#998ec3", linewidth=2)
    plt.legend((hB, hR), ('Normal', 'Fast Join'), loc="best", fontsize=30)
    hB.set_visible(False)
    hR.set_visible(False)
    # hL.set_visible(False)
    plt.tick_params(axis='both', which='major', labelsize=30, pad=15)
    plt.tick_params(axis='both', which='minor', labelsize=26, pad=15)
    plt.tight_layout()
    plt.savefig(os.path.join(output, 'fastjoin_msg_delays.pdf'))
    plt.close('all')

    plt.figure()
    plt.clf()
    ax = plt.axes()
    plt.hold(True)
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%"]["percCell"], positions=[1, 2], widths=0.6)
    setBoxColors(bp)
    plt.title('Percentage cellular used')
    plt.ylabel('Percentage cellular used')
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%"]["percCell"], positions=[4, 5], widths=0.6)
    setBoxColors(bp)
    plt.ylim(-5, 105)
    plt.xlim(0, 6)
    ax.set_xticklabels(['No loss', 'Loosing primary subflow'])
    ax.set_xticks([1.5, 4.5])
    # draw temporary red and blue lines and use them to create a legend
    hB, = plt.plot([1, 1], color="#bdbdbd", linewidth=2)
    hR, = plt.plot([1, 1], color="#636363", linewidth=2)
    # hL, = plt.plot([1, 1], color="#998ec3", linewidth=2)
    plt.legend((hB, hR), ('No oracle', 'Oracle'), loc="best", fontsize=30)
    hB.set_visible(False)
    hR.set_visible(False)
    # hL.set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(output, 'fastjoin_msg_perc_cell.pdf'))
    plt.close('all')

    plt.figure()
    plt.clf()
    ax = plt.axes()
    plt.hold(True)
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%"]["timeUsed"], positions=[1, 2], widths=0.6)
    setBoxColors(bp)
    plt.title('Percentage time cellular used')
    plt.ylabel('Percentage time cellular used')
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%"]["timeUsed"], positions=[4, 5], widths=0.6)
    setBoxColors(bp)
    plt.ylim(-5, 105)
    plt.xlim(0, 6)
    ax.set_xticklabels(['No loss', 'Loosing primary subflow'])
    ax.set_xticks([1.5, 4.5])
    # draw temporary red and blue lines and use them to create a legend
    hB, = plt.plot([1, 1], color="#bdbdbd", linewidth=2)
    hR, = plt.plot([1, 1], color="#636363", linewidth=2)
    # hL, = plt.plot([1, 1], color="#998ec3", linewidth=2)
    plt.legend((hB, hR), ('No oracle', 'Oracle'), loc="best", fontsize=30)
    hB.set_visible(False)
    hR.set_visible(False)
    # hL.set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(output, 'fastjoin_msg_time_used.pdf'))
    plt.close('all')

    plt.figure(figsize=(15, 5.5))
    plt.clf()
    ax = plt.axes()
    plt.hold(True)
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%"]["startCell"], positions=[1, 2], widths=0.6)
    setBoxColors(bp)
    # plt.title('Percentage time cellular on')
    plt.ylabel('Time cellular on (%)', fontsize=28)
    bp = plt.boxplot(results["0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%"]["startCell"], positions=[4, 5], widths=0.6)
    setBoxColors(bp)
    plt.ylim(-5, 105)
    plt.xlim(0, 6)
    ax.set_xticklabels(['No loss', 'Loosing primary subflow'])
    ax.set_xticks([1.5, 4.5])
    # draw temporary red and blue lines and use them to create a legend
    hB, = plt.plot([1, 1], color="#bdbdbd", linewidth=2)
    hR, = plt.plot([1, 1], color="#636363", linewidth=2)
    # hL, = plt.plot([1, 1], color="#998ec3", linewidth=2)
    plt.legend((hB, hR), ('No oracle', 'Oracle'), loc="best", fontsize=30)
    hB.set_visible(False)
    hR.set_visible(False)
    # hL.set_visible(False)
    plt.tick_params(axis='both', which='major', labelsize=30, pad=15)
    plt.tick_params(axis='both', which='minor', labelsize=26, pad=15)
    plt.tight_layout()
    plt.savefig(os.path.join(output, 'fastjoin_msg_start_cell.pdf'))
    plt.close('all')


def linePlot(mptcpValues, output_dir):
    configs = [
        ("512", "512 B", "blue", "o", "-"),
        ("1420", "1420 B", "orange", "v", "--"),
        ("4096", "4 KB", "#73D7D7", "D", "-."),
        ("16384", "16 KB", "green", "^", ":"),
    ]
    topos = [
        ("0_d7.5b10_1_d12.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 25),
        ("0_d7.5b10_1_d25b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 50),
        ("0_d7.5b10_1_d37.5b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 75),
        ("0_d7.5b10_1_d50b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 100),
        ("0_d7.5b10_1_d75b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 150),
        ("0_d7.5b10_1_d100b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 200),
        ("0_d7.5b10_1_d150b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 300),
        ("0_d7.5b10_1_d200b10_nt_0_0_loss_0%_nt_1_0_loss_0%_nt_0_7_loss_100%", 400),
    ]

    plt.clf()
    fig, ax = plt.subplots()
    fig.set_size_inches(15, 5.5)

    for pkt_bytes, configText, color, marker, ls in configs:
        x = []
        y = []
        ymin = []
        ymax = []

        for topo, x_val in topos:
            delays_0 = []
            delays_1 = []
            for item in mptcpValues[topo]["default-1_server"]["0-t1"]["0"][pkt_bytes]["olia"]:
                delays_0 += item["value"][0]

            for item in mptcpValues[topo]["default-1_server"]["0-t1"]["1"][pkt_bytes]["olia"]:
                delays_1 += item["value"][0]

            med_delay_0 = np.median(delays_0)
            med_delay_1 = np.median(delays_1)
            med_delay = med_delay_0 - med_delay_1
            # std_delay = np.std(delays)
            # min_delay = np.min(delays)
            min_delay_0 = np.percentile(delays_0, 25)
            min_delay_1 = np.percentile(delays_1, 25)
            min_delay = min_delay_0 - min_delay_1
            # max_delay = np.max(delays)
            max_delay_0 = np.percentile(delays_0, 75)
            max_delay_1 = np.percentile(delays_1, 75)
            max_delay = max_delay_0 - max_delay_1
            x.append(x_val)
            y.append(med_delay)
            ymin.append(med_delay - min_delay)
            ymax.append(max_delay - med_delay)

        print(ymin, ymax)
        eb1 = ax.errorbar(x, y, yerr=[ymin, ymax], color=color, label=configText, linewidth=2, marker=marker, linestyle=ls)
        eb1[-1][0].set_linestyle(ls)

    plt.xlabel("Additional path RTT [ms]", fontsize=30)
    plt.ylabel("Delta Max Delay [ms]", fontsize=28)
    plt.tick_params(axis='both', which='major', labelsize=30, pad=15)
    plt.tick_params(axis='both', which='minor', labelsize=26, pad=15)
    ax.legend(loc="best", fontsize=30)
    # plt.yscale("log")
    # plt.xscale("symlog")
    # plt.grid()
    ax.yaxis.grid() # horizontal lines
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fastjoin_msg_delta_delays.png'), transparent=True)
    # plt.savefig(os.path.join(output_dir, 'fastjoin_msg_delta_delays.pdf'))


extended_results_dir = os.path.abspath(args.results_dir)
if not os.path.exists(extended_results_dir) or not os.path.isdir(extended_results_dir):
    print("Invalid results directory " + extended_results_dir)
    sys.exit(1)

extended_output_dir = os.path.abspath(args.output_dir)
check_directory_exists(extended_output_dir)

tcpValues, mptcpValues = getSimpleTcpAndMptcpValues(results_directory=extended_results_dir, timeInLabel=False)
# boxPlot(mptcpValues, extended_output_dir)
linePlot(mptcpValues, extended_output_dir)
