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
PRIO_PATH_0 = "prioPath0"
PRIO_PATH_1 = "prioPath1"
BACKUP_PATH_0 = "backupPath0"
BACKUP_PATH_1 = "backupPath1"
METRIC = "metric"
EXPIRATION = "expiration"
USE_FASTJOIN = "useFastjoin"

""" XP TYPES """
HTTPS = "https"
HTTP = "http"
SIRI = "siri"
SIRIMSG = "sirimsg"
MSG = "msg"

""" Specific to https """
HTTPS_FILE = "file"
HTTPS_RANDOM_SIZE = "file_size"

""" Specific to http """
HTTP_FILE = "http_file"
HTTP_RANDOM_SIZE = "http_file_size"

""" Specific to siri """
SIRI_RUN_TIME = "siriRunTime"
SIRI_QUERY_SIZE = "siriQuerySize"
SIRI_RESPONSE_SIZE = "siriResponseSize"
SIRI_DELAY_QUERY_RESPONSE = "siriDelayQueryResponse"
SIRI_MIN_PAYLOAD_SIZE = "siriMinPayloadSize"
SIRI_MAX_PAYLOAD_SIZE = "siriMaxPayloadSize"
SIRI_INTERVAL_TIME_MS = "siriIntervalTimeMs"
SIRI_BUFFER_SIZE = "siriBufferSize"
SIRI_BURST_SIZE = "siriBurstSize"
SIRI_INTERVAL_BURST_TIME_MS = "siriIntervalBurstTimeMs"

""" Specific to Msg """
MSG_SERVER_SLEEP = "msgServerSleep"
MSG_CLIENT_SLEEP = "msgClientSleep"
MSG_NB_REQUESTS = "msgNbRequests"
MSG_BYTES = "msgBytes"

""" Default values """
DEFAULT_XP_TYPE = HTTP
DEFAULT_CLIENT_PCAP = "yes"
DEFAULT_SERVER_PCAP = "no"
DEFAULT_SNAPLEN_PCAP = "100"
DEFAULT_SCHEDULER = "default"
DEFAULT_CC = "olia"
DEFAULT_KERNEL_PATH_MANAGER_CLIENT = "fullmesh"
DEFAULT_KERNEL_PATH_MANAGER_SERVER = "fullmesh"
DEFAULT_EARLY_RETRANS = "3"
DEFAULT_EXPIRATION = "300"
DEFAULT_USE_FASTJOIN = "1"

""" Default values for specific fields to https """
DEFAULT_HTTPS_FILE = "random"
DEFAULT_HTTPS_RANDOM_SIZE = "1024"

""" Default values for specific fields to http """
DEFAULT_HTTP_FILE = "random"
DEFAULT_HTTP_RANDOM_SIZE = "1024"

""" Default values for specific fields to siri """
DEFAULT_SIRI_RUN_TIME = "30"
DEFAULT_SIRI_QUERY_SIZE = "2500"
DEFAULT_SIRI_RESPONSE_SIZE = "750"
DEFAULT_SIRI_DELAY_QUERY_RESPONSE = "0"
DEFAULT_SIRI_MIN_PAYLOAD_SIZE = "85"
DEFAULT_SIRI_MAX_PAYLOAD_SIZE = "500"
DEFAULT_SIRI_INTERVAL_TIME_MS = "333"
DEFAULT_SIRI_BUFFER_SIZE = "9"
DEFAULT_SIRI_BURST_SIZE = "0"
DEFAULT_SIRI_INTERVAL_BURST_TIME_MS = "0"

""" Default values for specific fields to msg """
DEFAULT_MSG_SERVER_SLEEP = "5.0"
DEFAULT_MSG_CLIENT_SLEEP = "5.0"
DEFAULT_MSG_NB_REQUESTS = "5"
DEFAULT_MSG_BYTES = "1200"


def fillHttpsInfo(xpFile, xpDict):
    print(HTTPS_FILE + ":" + str(xpDict.get(HTTPS_FILE, DEFAULT_HTTPS_FILE)), file=xpFile)
    print(HTTPS_RANDOM_SIZE + ":" + str(xpDict.get(HTTPS_RANDOM_SIZE, DEFAULT_HTTPS_RANDOM_SIZE)), file=xpFile)


def fillHttpInfo(xpFile, xpDict):
    print(HTTP_FILE + ":" + str(xpDict.get(HTTP_FILE, DEFAULT_HTTP_FILE)), file=xpFile)
    print(HTTP_RANDOM_SIZE + ":" + str(xpDict.get(HTTP_RANDOM_SIZE, DEFAULT_HTTP_RANDOM_SIZE)), file=xpFile)


def fillSiriInfo(xpFile, xpDict):
    print(SIRI_RUN_TIME + ":" + str(xpDict.get(SIRI_RUN_TIME, DEFAULT_SIRI_RUN_TIME)), file=xpFile)
    print(SIRI_QUERY_SIZE + ":" + str(xpDict.get(SIRI_QUERY_SIZE, DEFAULT_SIRI_QUERY_SIZE)), file=xpFile)
    print(SIRI_RESPONSE_SIZE + ":" + str(xpDict.get(SIRI_RESPONSE_SIZE, DEFAULT_SIRI_RESPONSE_SIZE)), file=xpFile)
    print(SIRI_DELAY_QUERY_RESPONSE + ":" + str(xpDict.get(SIRI_DELAY_QUERY_RESPONSE, DEFAULT_SIRI_DELAY_QUERY_RESPONSE)), file=xpFile)
    print(SIRI_MIN_PAYLOAD_SIZE + ":" + str(xpDict.get(SIRI_MIN_PAYLOAD_SIZE, DEFAULT_SIRI_MIN_PAYLOAD_SIZE)), file=xpFile)
    print(SIRI_MAX_PAYLOAD_SIZE + ":" + str(xpDict.get(SIRI_MAX_PAYLOAD_SIZE, DEFAULT_SIRI_MAX_PAYLOAD_SIZE)), file=xpFile)
    print(SIRI_INTERVAL_TIME_MS + ":" + str(xpDict.get(SIRI_INTERVAL_TIME_MS, DEFAULT_SIRI_INTERVAL_TIME_MS)), file=xpFile)
    print(SIRI_BUFFER_SIZE + ":" + str(xpDict.get(SIRI_BUFFER_SIZE, DEFAULT_SIRI_BUFFER_SIZE)), file=xpFile)
    print(SIRI_BURST_SIZE + ":" + str(xpDict.get(SIRI_BURST_SIZE, DEFAULT_SIRI_BURST_SIZE)), file=xpFile)
    print(SIRI_INTERVAL_BURST_TIME_MS + ":" + str(xpDict.get(SIRI_INTERVAL_BURST_TIME_MS, DEFAULT_SIRI_INTERVAL_BURST_TIME_MS)), file=xpFile)
    print(AUTOCORK + ":0", file=xpFile)


def fillMsgInfo(xpFile, xpDict):
    print(MSG_SERVER_SLEEP + ":" + str(xpDict.get(MSG_SERVER_SLEEP, DEFAULT_MSG_SERVER_SLEEP)), file=xpFile)
    print(MSG_CLIENT_SLEEP + ":" + str(xpDict.get(MSG_CLIENT_SLEEP, DEFAULT_MSG_CLIENT_SLEEP)), file=xpFile)
    print(MSG_NB_REQUESTS + ":" + str(xpDict.get(MSG_NB_REQUESTS, DEFAULT_MSG_NB_REQUESTS)), file=xpFile)
    print(MSG_BYTES + ":" + str(xpDict.get(MSG_BYTES, DEFAULT_MSG_BYTES)), file=xpFile)


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
    print(EXPIRATION + ":" + str(xpDict.get(EXPIRATION, DEFAULT_EXPIRATION)), file=xpFile)
    print(USE_FASTJOIN + ":" + str(xpDict.get(USE_FASTJOIN, DEFAULT_USE_FASTJOIN)), file=xpFile)
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

    if PRIO_PATH_0 in xpDict and PRIO_PATH_1 in xpDict:
        print(PRIO_PATH_0 + ":" + str(xpDict[PRIO_PATH_0]), file=xpFile)
        print(PRIO_PATH_1 + ":" + str(xpDict[PRIO_PATH_1]), file=xpFile)

    if BACKUP_PATH_0 in xpDict:
        print(BACKUP_PATH_0 + ":" + str(xpDict[BACKUP_PATH_0]), file=xpFile)

    if BACKUP_PATH_1 in xpDict:
        print(BACKUP_PATH_1 + ":" + str(xpDict[BACKUP_PATH_1]), file=xpFile)

    if METRIC in xpDict:
        print(METRIC + ":" + str(xpDict[METRIC]), file=xpFile)

    if xpType == HTTPS:
        fillHttpsInfo(xpFile, xpDict)
    elif xpType == HTTP:
        fillHttpInfo(xpFile, xpDict)
    elif xpType == SIRI:
        fillSiriInfo(xpFile, xpDict)
    elif xpType == SIRIMSG:
        fillMsgInfo(xpFile, xpDict)
        fillSiriInfo(xpFile, xpDict)
    elif xpType == MSG:
        fillMsgInfo(xpFile, xpDict)
    else:
        raise NotImplementedError("Experience not yet implemented: " + xpType)

    xpFile.close()