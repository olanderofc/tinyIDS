from StringIO import StringIO
from config import config
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
import os

class parsing:
    def __init__(self, thedir):
        self.ruledir = thedir
        self.rules = []
        self.tcprules = []
        self.udprules = []
        self.icmprules = []

    @staticmethod
    def writelog(msg):
        logging.info(msg)

    @staticmethod
    def getepoch():
        return str(int(time.time()))

    def gettcprules(self):
        return self.tcprules

    def getudprules(self):
        return self.udprules

    def getrules(self):
        return self.rules

    #Rule stuff should be moved to a separate class file in the future.
    def parserules(self):
        thedir = self.ruledir + '/*.json'
        rules = glob.glob(thedir)
        ruleid = []

        for rule in rules:
            try:
                with open(rule) as data_file:
                    data = json.load(data_file)
                    rule_id = data["rule_id"]
                    data["file_name"] = rule
                    if rule_id in ruleid:
                        print 'Duplicate rule ID. ID is already present in a rule. Please check rule: '+rule
                        exit()
                    else:
                        ruleid.append(rule_id)

                    self.rules.append(data)
                    if data["proto"] == 'tcp':
                        self.tcprules.append(data)
                    elif data["proto"] == 'udp':
                        self.udprules.append(data)
                    elif data["proto"] == 'icmp':
                        self.icmprules.append(data)
                    else:
                        pass

            except:
                print 'Rule error. Please check rule '+rule
                os._exit(0)

        for rule in self.rules:
            if rule["enabled"] == "yes":
                self.writelog("Rule '"+rule["rule_name"]+"' with ID '"+str(rule["rule_id"])+"' is enabled and loaded")
