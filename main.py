from parsing import parsing
from feed import feed
from updater import updater
from commander import commander
from filter import filter
from statistics import statistics
from inspect import inspect
from config import config
from Queue import *
from controller import controller
from dbhandler import dbhandler

import dpkt, pcap, socket
import traceback
import logging
import thread
import time
import logging.handlers
import os

VERSION = "0.5"


def writelog(msg):
    logging.info(msg)


def gettime():
    t = time.localtime()
    return "%s " % time.asctime(t)


def main():

    cfg = config()

    log_filename = cfg.getlogfile()
    rule_dir = cfg.getruledir()
    feed_dir = cfg.getfeeddir()
    captureifc = cfg.getinterface()
    trafficfilter = cfg.getfilters()

    my_logger = logging.getLogger('tinyIDS')
    handler = logging.handlers.RotatingFileHandler(log_filename, maxBytes=20, backupCount=5)
    my_logger.addHandler(handler)
    logging.basicConfig(format='%(asctime)s %(message)s', filename=log_filename,level=logging.INFO)

    writelog("Starting tinyIDS "+VERSION+" at "+gettime())

    writelog("tinyIDS configured with virustotal API key " + cfg.getvtapikey())
    #Start the packet capture
    if len(captureifc) > 0:
        pc = pcap.pcap(name=captureifc)
    else:
        pc = pcap.pcap()

    if len(trafficfilter) > 0:
        try:
            pc.setfilter(trafficfilter)
            writelog("Using traffic filter: '"+trafficfilter+"'")
        except:
            writelog("Unable to set traffic filter, probably wrong syntax")
            os._exit(0)

    writelog("Reading rules")
    p = parsing(rule_dir)
    p.parserules()
    rules = p.getrules()
    #Some information is written to the log regarding what rules are loaded.
    writelog("Done reading rules")
    writelog("Reading IP lists from feed directory")

    tcprules = p.gettcprules()
    udprules = p.getudprules()

    #Create the threat feed object
    f = feed(feed_dir)
    f.parsefeed()

    #Create the commander object
    cmd = commander(log_filename)

    stat = statistics()
    #Will be used to handle filters, but not implemented yet.
    fil = filter()
    fil.getfiltersfromdb()

    #The action object will be used to inspect stuff
    act = inspect()

    #The controller
    ctrl = controller()

    #The IP feed update object
    update = updater()

    #This starts the command thread.
    try:
        thread.start_new_thread( cmd.menu, (f,rules,stat,fil,update,) )
        writelog("Started command thread")
    except:
        print traceback.print_exc()
        writelog("Unable to start command thread")

    inspectq = LifoQueue(0)
    maliconnq = LifoQueue(0)
    packetlog = Queue(0)

    try:
        thread.start_new_thread(update.startupdate, (f,) )
        writelog("Started auto update thread")
    except:
        print traceback.print_exc()
        writelog("Unable to start update thread")

    try:
        thread.start_new_thread( act.maliciousconn, (maliconnq,f, ) )
        writelog("Started malicious communication thread")
    except:
        print 'Unable to start connection inspection thread'
        print traceback.print_exc()

    #This starts the thread that will inspect traffic against signatures.
    try:
        thread.start_new_thread( act.inspect, (inspectq, rules, stat, p, udprules, tcprules, fil, packetlog,  ) )
        writelog("Started inspection thread")
    except:
        print 'Unable to start packet inspection thread'
        print traceback.print_exc()
    #Start the controller thread
    try:
        thread.start_new_thread( ctrl.handle, (inspectq, maliconnq, packetlog, ) )
        writelog("Staring controller thread")
    except:
        print 'Unable to start packet controller thread'
        print traceback.print_exc()


    dbhand = dbhandler()
    tcpexclusions = dbhand.getexclusions(6)
    udpexclusions = dbhand.getexclusions(17)

    for exclusion in tcpexclusions:
        writelog("Excluding all traffic for TCP port: "+str(int(exclusion["port"])))
        if exclusion["port"] > 1024:
            writelog("Warning. A port higher than 1024 is set for TCP exclusions. This could cause tinyIDS to not inspect relevant traffic")

    for exclusion in udpexclusions:
        writelog("Excluding all traffic for TCP port: "+str(int(exclusion["port"])))
        if exclusion["port"] > 1024:
            writelog("Warning. A port higher than 1024 is set for UDP exclusions. This could cause tinyIDS to not inspect relevant traffic")

    inspectpkt = True

    for ts, pkt in pc:
        try:
            #Get a packet
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                #Get the data part
                ip = eth.data
                if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
                    sourceport = str(ip.data.sport)
                    destport = str(ip.data.dport)

                    #Match against any exclusions of specific traffic.
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        for port in tcpexclusions:
                            if int(port["port"]) == int(destport) or int(port["port"]) == int(sourceport):
                                inspectpkt = False
                                break

                    if ip.p == dpkt.ip.IP_PROTO_UDP:
                        for port in udpexclusions:
                            if int(port["port"]) == int(destport) or int(port["port"]) == int(sourceport):
                                inspectpkt = False
                                break

                    #All packets are sent to both queues so that they are inspected separately.
                    if inspectpkt:
                        inspectq.put(eth)
                        packetlog.put(eth,True)
                    else:
                        inspectpkt = True

                    #Always check for communication.
                    maliconnq.put(eth)

        except:
            #Exceptions are discarded
            continue


if __name__ == '__main__':
    main()
    writelog("Quitting")
	
