#! /usr/bin/python

from __future__ import print_function

import collections

XP_TYPE = "xpType"
CLIENT_PCAP = "clientPcap"
SERVER_PCAP = "serverPcap"
SNAPLEN_PCAP = "snaplenPcap"
SCHEDULER = "sched"
SCHEDULER_CLIENT = "schedc"
SCHEDULER_SERVER = "scheds"
CC = "congctrl"
KERNEL_PATH_MANAGER_CLIENT = "kpmc"
KERNEL_PATH_MANAGER_SERVER = "kpms"
RMEM = "rmem"
WMEM = "wmem"
AUTOCORK = "autocork"
EARLY_RETRANS = "earlyRetrans"

""" XP TYPES """
HTTPS = "https"
QUIC = "quic"
QUICREQRES = "quicreqres"

""" Specific to https """
HTTPS_FILE = "file"
HTTPS_RANDOM_SIZE = "file_size"

""" Specific to all QUIC experiences """
QUIC_MULTIPATH = "quicMultipath"

""" Specific to QUIC reqres experiences """
QUICREQRES_RUN_TIME = "quicReqresRunTime"

""" Default values """
DEFAULT_XP_TYPE = HTTPS
DEFAULT_CLIENT_PCAP = "yes"
DEFAULT_SERVER_PCAP = "no"
DEFAULT_SNAPLEN_PCAP = "100"
DEFAULT_SCHEDULER = "default"
DEFAULT_CC = "olia"
DEFAULT_KERNEL_PATH_MANAGER_CLIENT = "fullmesh"
DEFAULT_KERNEL_PATH_MANAGER_SERVER = "fullmesh"
DEFAULT_EARLY_RETRANS = "3"

""" Default values for specific fields to https """
DEFAULT_HTTPS_FILE = "random"
DEFAULT_HTTPS_RANDOM_SIZE = "1024"

""" Default values for specific fields to all QUIC experiences """
DEFAULT_QUIC_MULTIPATH = "0"

""" Default values for specific fields to QUIC siri """
DEFAULT_QUICREQRES_RUN_TIME = "30"


def fillHttpsInfo(xpFile, xpDict):
    print(HTTPS_FILE + ":" + str(xpDict.get(HTTPS_FILE, DEFAULT_HTTPS_FILE)), file=xpFile)
    print(HTTPS_RANDOM_SIZE + ":" + str(xpDict.get(HTTPS_RANDOM_SIZE, DEFAULT_HTTPS_RANDOM_SIZE)), file=xpFile)


def fillCommonQUICInfo(xpFile, xpDict):
    print(QUIC_MULTIPATH + ":" + str(xpDict.get(QUIC_MULTIPATH, DEFAULT_QUIC_MULTIPATH)), file=xpFile)


def fillQUICInfo(xpFile, xpDict):
    fillCommonQUICInfo(xpFile, xpDict)
    print(HTTPS_FILE + ":" + str(xpDict.get(HTTPS_FILE, DEFAULT_HTTPS_FILE)), file=xpFile)
    print(HTTPS_RANDOM_SIZE + ":" + str(xpDict.get(HTTPS_RANDOM_SIZE, DEFAULT_HTTPS_RANDOM_SIZE)), file=xpFile)


def fillQUICReqresInfo(xpFile, xpDict):
    fillCommonQUICInfo(xpFile, xpDict)
    print(QUICREQRES_RUN_TIME + ":" + str(xpDict.get(QUICREQRES_RUN_TIME, DEFAULT_QUICREQRES_RUN_TIME)), file=xpFile)


def generateXpFile(xpFilename, xpDict):
    xpFile = open(xpFilename, 'w')
    xpType = xpDict.get(XP_TYPE, DEFAULT_XP_TYPE)
    """ First set common information for any experience """
    print(XP_TYPE + ":" + xpType, file=xpFile)
    print(CLIENT_PCAP + ":" + xpDict.get(CLIENT_PCAP, DEFAULT_CLIENT_PCAP), file=xpFile)
    print(SERVER_PCAP + ":" + xpDict.get(SERVER_PCAP, DEFAULT_SERVER_PCAP), file=xpFile)
    print(SNAPLEN_PCAP + ":" + xpDict.get(SNAPLEN_PCAP, DEFAULT_SNAPLEN_PCAP), file=xpFile)
    if SCHEDULER_CLIENT in xpDict and SCHEDULER_SERVER in xpDict:
        print(SCHEDULER_CLIENT + ":" + str(xpDict[SCHEDULER_CLIENT]), file=xpFile)
        print(SCHEDULER_SERVER + ":" + str(xpDict[SCHEDULER_SERVER]), file=xpFile)
    else:
        print(SCHEDULER + ":" + xpDict.get(SCHEDULER, DEFAULT_SCHEDULER), file=xpFile)
    print(CC + ":" + xpDict.get(CC, DEFAULT_CC), file=xpFile)
    print(KERNEL_PATH_MANAGER_CLIENT + ":" + xpDict.get(KERNEL_PATH_MANAGER_CLIENT, DEFAULT_KERNEL_PATH_MANAGER_CLIENT), file=xpFile)
    print(KERNEL_PATH_MANAGER_SERVER + ":" + xpDict.get(KERNEL_PATH_MANAGER_SERVER, DEFAULT_KERNEL_PATH_MANAGER_SERVER), file=xpFile)
    print(EARLY_RETRANS + ":" + str(xpDict.get(EARLY_RETRANS, DEFAULT_EARLY_RETRANS)), file=xpFile)
    """ Set rmem if defined (assume as string, int or iterable) """
    if RMEM in xpDict:
        rmemRaw = xpDict[RMEM]
        if isinstance(rmemRaw, int):
            rmem = (rmemRaw, rmemRaw, rmemRaw)
        elif isinstance(rmemRaw, str) or (isinstance(rmemRaw, collections.Iterable) and len(rmemRaw) == 3):
            # Assume it's ok
            rmem = rmemRaw
        else:
            raise Exception("Formatting error for rmem: " + str(rmemRaw))

        print(RMEM + ":" + str(rmem[0]), str(rmem[1]), str(rmem[2]), file=xpFile)

    if xpType == HTTPS:
        fillHttpsInfo(xpFile, xpDict)
    elif xpType == QUIC:
        fillQUICInfo(xpFile, xpDict)
    elif xpType == QUICREQRES:
        fillQUICReqresInfo(xpFile, xpDict)
    else:
        raise NotImplementedError("Experience not yet implemented: " + xpType)

    xpFile.close()


if __name__ == '__main__':
    xpHttpsDict = {
        XP_TYPE: HTTPS,
        HTTPS_RANDOM_SIZE: "2048"
    }
    generateXpFile("my_https_xp", xpHttpsDict)
