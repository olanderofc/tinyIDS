import thread
import logging
import socket
import dpkt
import time
import json
import glob
import binascii
import base64
import gzip
import dpkt, pcap, socket
import traceback
import logging
import re
import time
from IPy import IP
from Queue import *
from StringIO import StringIO
from config import config
from dbhandler import dbhandler

class inspect:

    def __init__(self):
        self.dbhand = dbhandler()
        self.cfg = config()

    @staticmethod
    def writelog(msg):
        logging.info(msg)

    @staticmethod
    def getepoch():
        return str(int(time.time()))

    # This function is used to match IP's against IP's from the threat urls.
    # q = the packet queue
    # feed = the list of IP's to match on
    def maliciousconn(self,q,feed):
        while True:
            eth = q.get()
            ip = eth.data
            if type(ip) is str:
                q.task_done()
                continue

            try:
                #If source and destination is private IP's. Dont inspect.
                ipsrc = IP(str(socket.inet_ntoa(ip.src)))
                ipdst = IP(str(socket.inet_ntoa(ip.dst)))
                if ipsrc.iptype() == 'PRIVATE' and ipdst.iptype() == 'PRIVATE':
                    q.task_done()
                    continue
            except:
                pass
            #Match against threat feeds
            if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
                #if type(proto) is dpkt.tcp.TCP or type(proto) is dpkt.udp.UDP:
                try:
                    #Get source and destination IP
                    sourceip = str(socket.inet_ntoa(ip.src))
                    destip = str(socket.inet_ntoa(ip.dst))
                    #Check against ip lists
                    if feed.checkinlist(destip) or feed.checkinlist(sourceip):
                        #Get source and destination ports
                        sourceport = str(ip.data.sport)
                        destport = str(ip.data.dport)
                        epochtime = self.getepoch()
                        #alertid = self.dbhand.addmalalert(time, str(socket.inet_ntoa(ip.src)), str(socket.inet_ntoa(ip.dst)), str(ip.data.sport), str(ip.data.dport) )
                        alertid = self.dbhand.addmalcomalert(ip,str(socket.inet_ntoa(ip.src)), str(socket.inet_ntoa(ip.dst)), str(ip.data.sport), str(ip.data.dport) )
                        alertdata = "[Threat Alert] ["+alertid+"] Communication with malicious host. Source: "+str(sourceip)+"/"+str(sourceport)+" Destination: "+str(destip)+"/"+str(destport)
                        self.writelog(alertdata)
                        if alertid != -1:
                            fname = str(alertid)+"_"+epochtime+"_maliciouscomm_" +sourceip+"_"+destip
                            self.writepacket(eth,fname,None)
                except:
                    q.task_done()
                    continue
            q.task_done()
    # Not used yet
    @staticmethod
    def httpinspect(proto):
        #Under construction - https://github.com/jeffsilverm/dpkt_doc
        if proto.dport == 80 and len(proto.data) > 0:
            doinspect = False
            try:
                http = dpkt.http.Request(proto.data)
                if 'host' and 'user-agent' in http.headers:
                    host = http.headers['host']
                    usera = http.headers['user-agent']
                    if host.startswith('http://') is False:
                        doinspect = True
                        print usera
                    #url = "http://"+host+http.uri
                if doinspect:
                    print http.putqurl
            except:
                pass

    #	if proto.sport == 80 and len(proto.data) > 0:
    #		try:
    #			http_r = dpkt.http.Response(proto.data)
    #			print http_r.data
    #		except:
    #			pass
    # This function is used to gzip up data found in HTTP packets with content-encoding set to gzip
    # data = the data from the packet.
    @staticmethod
    def gzipup(data):
        newline = '0d0a0d0a'
        magic = '1f8b'
        hexdata = binascii.hexlify(data)
        pattern = newline + magic
        if newline in hexdata:
            packet = hexdata.split(newline)
            if len(packet) == 2:
                packeddata = packet[1]
                if packeddata.startswith(magic):
                    try:
                        unpacked = binascii.unhexlify(packeddata)
                        buf = StringIO(unpacked)
                        tmpfile = gzip.GzipFile(fileobj=buf)
                        data = tmpfile.read(len(unpacked))
                        return data
                    except:
                        return data

        return data


    def writepacketlog(self, packet, fname, packetlog):
        if packetlog is None:
            return None

        try:
            #One issue here is that packets that are not matched will be thrown away. one alert cleans "packages" from another.
            #Old packages should repopulate the queue or something...copy.deepcopy does not work.
            ip = packet.data
            sourceip = str(socket.inet_ntoa(ip.src))
            destip = str(socket.inet_ntoa(ip.dst))
            #Get source and destination ports
            #If you do not deepcopy, then the packetlog will be cleared.
            #output = dpkt.pcap.Writer(open(cfg.getpcapdir()+fname+'.pcap','wb'))
            count = 0
            self.writelog("Writing packet capture")
            output = dpkt.pcap.Writer(open(self.cfg.getpcapdir()+fname+'_full.pcap','a'))

            while not packetlog.empty():

                if packetlog.qsize() <= 2:
                    break
                if count == 100:
                    break

                eth = packetlog.get()
                ip = eth.data

                if type(ip) is str:
                    packetlog.task_done()
                    continue
                elif len(eth) <= 0:
                    packetlog.task_done()
                    continue
                else:
                    pass

                if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
                    #               if type(proto) is dpkt.tcp.TCP or type(proto) is dpkt.udp.UDP:
                    try:
                        tmpsourceip = str(socket.inet_ntoa(ip.src))
                        tmpdestip = str(socket.inet_ntoa(ip.dst))
                        if tmpsourceip == sourceip or tmpsourceip == destip:
                            if tmpdestip == destip or tmpdestip == sourceip:
                                output.writepkt(eth)
                                count += 1
                    except:
                        pass

                packetlog.task_done()

            self.writelog("Done writing packet capture")
            output.close()
        except:
            print traceback.print_exc()
            self.writelog("ERROR Unable to dump full traffic capture to pcap file. Check permissions and folder settings for pcap directory")


    # This function is used when the .pcap is created when an alert is generated.
    # packet = The one packet that has triggered an alert
    # fname = The file name of the pcap
    # packetlog = The full packetlog (the size of which you set in the .cfg file)
    def writepacket(self, packet, fname, packetlog = None):
        try:
            #One issue here is that packets that are not matched will be thrown away. one alert cleans "packages" from another.
            #Old packages should repopulate the queue or something...copy.deepcopy does not work.
            ip = packet.data
            #Get source and destination ports
            #If you do not deepcopy, then the packetlog will be cleared.
            #output = dpkt.pcap.Writer(open(cfg.getpcapdir()+fname+'.pcap','wb'))
            triggerpacket = dpkt.pcap.Writer(open(self.cfg.getpcapdir()+fname+'_tp.pcap','wb'))
            triggerpacket.writepkt(packet)
            triggerpacket.close()
            self.writepacketlog(packet, fname, packetlog)
        except:
            print traceback.print_exc()
            self.writelog("ERROR  Unable to dump alert traffic to pcap file. Check permissions and folder settings for pcap directory")

    # This function will find if a packet is filtered in the filters
    # filters = All of the filters
    # ipheader = The ip header, ip, source/dest port etc.
    # signature = The signature to match against the filters.
    @staticmethod
    def isfiltered(filters,ipheader,signature):
        sourceip = str(socket.inet_ntoa(ipheader.src))
        destip = str(socket.inet_ntoa(ipheader.dst))
        sourceport = str(ipheader.data.sport)
        destport = str(ipheader.data.dport)
        for filter in filters:
            if filter["rule_id"] == signature["rule_id"]:
                if sourceip == filter["source"]:
                    if destip == filter["dest"]:
                        if sourceport == str(filter["sport"]) or filter["sport"] == 0:
                            if destport == str(filter["dport"]) or filter["dport"] == 0:
                                return True
        return False

    # When we are sure that we want to generate an alert. This function does that
    # packet = The data packet that caused the alert.
    # hexpacket = The actual data that triggered. Not used?!?!?
    # etherpacket = The full packet to be written to .pcap file
    # packetlog = The available packetlog
    def genalert(self, packet, hexpacket, sig, ipheader, etherpacket, packetlog):
        b64packet = base64.b64encode(packet)
        sourceip = str(socket.inet_ntoa(ipheader.src))
        destip = str(socket.inet_ntoa(ipheader.dst))
        sourceport = str(ipheader.data.sport)
        destport = str(ipheader.data.dport)
        epochtime = self.getepoch()
        #alertid = self.dbhand.addalert(time, sig["rule_id"], sig['rule_name'] , b64packet)
        alertid = self.dbhand.addalert(ipheader, sig["rule_id"] , sig['rule_name'], b64packet, sourceip, destip, sourceport, destport)
        if alertid != -1:
            self.writelog( str("[IDS Alert] ID:"+str(alertid)+" Time: "+epochtime+" Rule: '"+sig['rule_name']+"' Source: "+sourceip+"/"+sourceport+" Destination: "+destip+"/"+destport+" Data: '"+b64packet+"'") )
            fname = str(alertid)+"_"+epochtime+"_"+sig['rule_name'] + "_" +sourceip+"_"+destip
            self.writepacket(etherpacket,fname,packetlog)

    # This function will do the actual matching of a signature against a packet
    # packet = The packet to match on
    # signature = The signature to match on
    # ipheader = The ip header data
    # etherpacket = The complete packet
    # filters = All of the filters
    # packetlog = The complete packetlog
    def match(self, packet, signature, ipheader, etherpacket, filters, packetlog):
        #print packetlog.qsize()
        #Is the sig enabled or not.
        if signature["enabled"] == 'no':
            return False
        if len(filters.getfilters()) > 0:
            #Check for any filters for this packet and signature.
            if self.isfiltered(filters.getfilters(), ipheader, signature):
                return False

        #Keep the full signature in memory
        sig = signature
        #Only get the data part to match
        signature = signature["data"]
        #Conver the packet to be analyzed to hex
        hexpacket = binascii.hexlify(packet)
        #If the signature contains OR statements (|) we check all signatures
        if "|" in signature and sig["regexp"] == "no":
            signatures = signature.split('|')
            for sign in signatures:
                if sign.lower() in hexpacket:
                    self.genalert(packet,hexpacket,sig,ipheader,etherpacket, packetlog)
                    return True
                else:
                    return False
        else:
            if sig["regexp"] == "no":
                if signature.lower() in hexpacket:
                    self.genalert(packet,hexpacket,sig,ipheader,etherpacket, packetlog)
                    return True
                else:
                    return False
            else:
                regexp = re.compile(sig["data"])
                match = regexp.search(str(packet))
                #matchto = regexpto.search(str(packet))
                #match = re.match(b'[sig["data"]]',bytearray(packet), re.MULTILINE)

                if match:
                    self.genalert(packet,hexpacket,sig,ipheader,etherpacket, packetlog)
                    return True
                else:
                    return False

    def trigger(self, parsing, packetdata, rule, ip, etherpacket, filters, packetlog):

        if self.match(packetdata, rule, ip, etherpacket, filters, packetlog):
            return True
        else:
            return False

    def inspect(self, q, rules, stat, p, udprules, tcprules, filters, packetlog):
        cfg = config()
        BUFSIZE = cfg.gettrafficbuffer()
        #print BUFSIZE
        while True:
            eth = q.get()
            ip = eth.data

            if packetlog.qsize() >= BUFSIZE:
                tmp = packetlog.get()

            #if type(ip) is str:
            #	q.task_done()
            #	continue
            #else:
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                proto = ip.data
                #It would be great to inspect HTTP requests and find malicious content.
                self.httpinspect(proto)
                #if type(proto) is dpkt.tcp.TCP:
                if proto.dport > 0 and proto.sport > 0:
                    for rule in tcprules:
                        if rule["enabled"] == 'yes':
                            if proto.dport == rule["dport"] or proto.sport == rule["sport"]:
                                #if True:
                                unpacked = self.gzipup(proto.data)
                                if unpacked != proto.data:
                                    if self.trigger(p, unpacked, rule, ip, eth, filters, packetlog):
                                        q.task_done()
                                        continue
                                elif self.trigger(p, proto.data, rule, ip, eth, filters, packetlog):
                                    q.task_done()
                                    continue
                                    #Inspection of UDP traffic
            #elif type(proto) is dpkt.udp.UDP:
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                proto = ip.data
                #stat.updatedport(proto.dport)
                #stat.updatesport(proto.sport)
                for rule in udprules:
                    if rule["enabled"] == 'yes':
                        if proto.dport > 0 and proto.sport > 0:
                            if proto.dport == rule["dport"] or proto.sport == rule["sport"]:
                                if self.trigger(p, proto.data, rule, ip, eth, filters, packetlog):
                                    q.task_done()
                                    continue
            #Other protocols such as ARP
            else:
                q.task_done()
                continue
	
