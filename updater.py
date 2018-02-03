from IPy import IP
from config import config
import glob
import logging
import urllib2
import traceback
import random
import time
import os
import re

class updater:
    def __init__(self):
        self.iplist = []
        self.sleeptime = 0

    @staticmethod
    def writelog(msg):
        logging.info(msg)

    def changetime(self, newtime):
        self.sleeptime = float(newtime)
        self.writelog("Update time changed to "+str(newtime)+" minutes and will be enabled after next update")

    def gettime(self):
        return self.sleeptime

    def startupdate(self, feedobj):
        cfg = config()
        sleeptime = cfg.getfeedtime()
        try:
            sleeptime = float(sleeptime)
        except:
            self.writelog("Unable to set update time. Please refer to cfg file and parameter 'feedupdate'")
            self.writelog("Quitting tinyIDS")
            os._exit(0)

        self.writelog("Feed auto update set to "+str(sleeptime)+" minutes")
        if sleeptime < 30:
            self.writelog("Warning. You have set the sleeptime to under 30 minutes.")

        self.sleeptime = sleeptime

        while True:
            self.iplist = []
            for feedurl in feedobj.getthreaturls():
                try:
                    self.writelog("Downloading "+feedurl[0]+" ")
                    for line in urllib2.urlopen(feedurl[0]):
                        line = line.replace('\n','')
                        ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                        for ipaddr in ip_candidates:
                            ip = IP(ipaddr)
                            if ip.iptype() != 'PRIVATE':
                                if ipaddr not in self.iplist:
                                    self.iplist.append(ipaddr)
                except urllib2.HTTPError, err:
                    self.writelog("Error! Download of list "+feedurl[1]+" failed with error "+str(err.code))

                except urllib2.URLError, err:
                    self.writelog("Error! Download of list"+feedurl[1]+" failed with error "+str(err.reason))
                else:
                    self.writelog("Success! Download of list "+feedurl[1]+" complete")
            self.writelog("List of threat IP's "+str(len(self.iplist)))
            self.writelog("Feed update is done.")
            feedobj.replacefeed(self.iplist)
            self.writelog("Feed has been updated in sensor")
            self.writelog("Sleeping for "+str(self.sleeptime)+" minutes before next download")
            time.sleep(self.sleeptime * float(60))


