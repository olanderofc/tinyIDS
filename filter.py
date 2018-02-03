from parsing import parsing
from feed import feed
from IPy import IP
from tabulate import tabulate
import traceback
from dbhandler import dbhandler

class filter:

    def __init__(self):
        self.dbhand = dbhandler()
        self.filters = []

    def  __str__(self):
        tableval = []
        headers = ['Filter ID','Source IP','Destination IP','Source Port','Destination Port','Rule ID']
        for fil in self.filters:
            data = [str(fil["_id"]), str(fil["srcip"]), str(fil["dstip"]), str(fil["srcport"]), str(fil["dstport"]),
                    str(fil["rule_id"])]
            tableval.append(data)

        return tabulate(tableval,headers,stralign='left',numalign='left')

    def getfilters(self):
        return self.filters

    def delfilter(self,filterid):
        self.dbhand.delfilter(filterid)
        self.getfiltersfromdb()

    @staticmethod
    def validateip(ipaddr):
        try:
            ip = IP(ipaddr)
        except:
            print 'Unable to add. Is the IP correct?'
            return False

        return True

    @staticmethod
    def validateport(port):
        try:
            if 65536 > port > -1:
                return True
        except:
            print 'Not a valid port'
            return False

        return True

    def validate(self, sourceip, destip, sport, dport, rule_id):
        add = False
        if self.validateip(sourceip) and self.validateip(destip):
            if self.validateport(sport) and self.validateport(dport):
                add = True
        if add:
            self.addfilter(sourceip, destip, sport, dport, rule_id)
            print 'Your filter has been added to the database.'
        else:
            print 'You have not entered valid data. Please make sure your data is correct.'


    def addfilter(self, sourceip, destip, sport, dport, rule_id):
        self.dbhand.addfilter(sourceip, destip, sport, dport, rule_id)
        self.getfiltersfromdb()

    def getfiltersfromdb(self):
        filters = self.dbhand.getfilters()
        self.filters = filters
