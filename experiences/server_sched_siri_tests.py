#! /usr/bin/python

from __future__ import print_function

# Doing * imports is bad :'(
from core.generate_topo import *
from core.generate_xp import *

import core.core as core
import os

REMOTE_SERVER_RUNNER_HOSTNAME = ["mininet@localhost"]
REMOTE_SERVER_RUNNER_PORT = ["8022"]


def getPostProcessingList(**kwargs):
    toReturn = []
    topoBasename = os.path.basename(kwargs["topoAbsPath"])
    toReturn.append(("client.pcap",
                     "_".join([str(x) for x in [kwargs["testDirectory"], kwargs["scheduler"][0], kwargs["scheduler"][1], kwargs["openBup"],
                                                kwargs["congestionControl"], topoBasename, "client.pcap"]])))
    toReturn.append(("server.pcap",
                     "_".join([str(x) for x in [kwargs["testDirectory"], kwargs["scheduler"][0], kwargs["scheduler"][1], kwargs["openBup"],
                                                kwargs["congestionControl"], topoBasename, "server.pcap"]])))
    toReturn.append(("command.log", "command.log"))
    toReturn.append(("ping.log", "ping.log"))
    toReturn.append(("siri_client.log", "siri_client.log"))
    toReturn.append(("siri_client.err", "siri_client.err"))
    toReturn.append(("siri_server.log", "siri_server.log"))
    toReturn.append(("netstat_client_before", "netstat_client_before"))
    toReturn.append(("netstat_server_before", "netstat_server_before"))
    toReturn.append(("netstat_client_after", "netstat_client_after"))
    toReturn.append(("netstat_server_after", "netstat_server_after"))

    return toReturn


def siriTests(topos, schedulers=["default"], congestionControls=["olia"], protocol="mptcp", tmpfs="/mnt/tmpfs"):
    experienceLauncher = core.ExperienceLauncher(REMOTE_SERVER_RUNNER_HOSTNAME, REMOTE_SERVER_RUNNER_PORT)

    def testsScheduler(**kwargs):
        def testsOpenBup(**kwargs):
            def testsCc(**kwargs):
                def test(**kwargs):
                    client_sched, server_sched = kwargs["scheduler"]
                    sched_list = client_sched.split("-")
                    xpDict = {
                        XP_TYPE: SIRI,
                        SCHEDULER_CLIENT: sched_list[0],
                        SCHEDULER_SERVER: server_sched,
                        CC: kwargs["congestionControl"],
                        CLIENT_PCAP: "yes",
                        SERVER_PCAP: "yes",
                        SIRI_RUN_TIME: 30,
                        SIRI_QUERY_SIZE: 2500,
                        SIRI_RESPONSE_SIZE: 750,
                        SIRI_DELAY_QUERY_RESPONSE: 0,
                        SIRI_MIN_PAYLOAD_SIZE: 85,
                        SIRI_MAX_PAYLOAD_SIZE: 500,
                        SIRI_INTERVAL_TIME_MS: 333,
                        SIRI_BUFFER_SIZE: 9,
                        RMEM: (10240, 87380, 16777216)
                    }
                    if len(sched_list) > 1:
                        if sched_list[1] == "0":
                            xpDict[BACKUP_PATH_0] = 1
                        elif sched_list[1] == "1":
                            xpDict[BACKUP_PATH_1] = 1

                    kwargs["postProcessing"] = getPostProcessingList(**kwargs)
                    core.experiment(experienceLauncher, xpDict, **kwargs)

                core.experimentFor("congestionControl", congestionControls, test, **kwargs)

            core.experimentFor("openBup", ["0"], testsCc, **kwargs)

        core.experimentFor("scheduler", schedulers, testsOpenBup, **kwargs)

    core.experimentTopos(topos, "siri", protocol, tmpfs, testsScheduler)
    experienceLauncher.finish()


def launchTests(times=5):
    """ Notice that the loss must occur at time + 2 sec since the minitopo test waits for 2 seconds between launching the server and the client """
    topos = [
        {PATHS: [{DELAY: 7.5, BANDWIDTH: 10}, {DELAY: 12.5, BANDWIDTH: 10}], NETEM: [(0, 0, "loss 0%"), (1, 0, "loss 0%")]},
        {PATHS: [{DELAY: 7.5, BANDWIDTH: 10}, {DELAY: 12.5, BANDWIDTH: 10}], NETEM: [(0, 0, "loss 0%"), (1, 0, "loss 0%"), (0, 7, "loss 100%")]},
    ]

    for i in range(times):
        siriTests(topos, protocol="mptcp", schedulers=[("default-1", "default"), ("default-1", "server")], congestionControls=["olia"])

launchTests(times=25)
