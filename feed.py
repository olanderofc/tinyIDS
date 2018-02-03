from IPy import IP
from config import config
import glob
import logging
import urllib2
import re
import traceback

class feed:
    def __init__(self, thedir):
        self.feeddir = thedir
        self.iplist = []
        self.known = []
        self.lists = []
        self.initfeedupdates()
        self.iplistcache = []
        self.doupdate = False

    def initfeedupdates(self):
        self.lists.append(["https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist","Zeuztracker blocklist"])
        self.lists.append(["https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist", "Spyeye blocklist"])
        self.lists.append(["https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist", "Palevo blocklist"])

    def addurltolist(self, description, url):
        #URL can only be 100 chars
        if len(url) < 100:
            self.lists.append([description, url])
        else:
            print 'Unable to add. URL is too long (max 100 chars)'

    def getthreaturls(self):
        return self.lists

    def download(self, url):
        print "Download data from "+url+"?"
        x = raw_input('Yes/No: ')
        if x == 'Yes' or x == 'yes':
            print 'Downloading'
            try:
                ipaddrlist = []
                count = 0

                for line in urllib2.urlopen(url):
                    line = line.replace('\n','')
                    ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                    for ipaddr in ip_candidates:
                        ip = IP(ipaddr)
                        if ip.iptype() != 'PRIVATE':
                            count += 1
                            ipaddrlist.append(ipaddr)

                print 'Download complete. Total IPs: '+str(count)
                x = raw_input('View list? Yes/No ')
                if x == 'Yes' or x == 'yes':
                    for ip in ipaddrlist:
                        print ip

                z = raw_input('Add all IPs to current threat list? Yes/No: ')

                if z == 'Yes' or z == 'yes':
                    for ip in ipaddrlist:
                        self.iplist.append(ip)
                    print 'Successfully added to current threat list'

                elif z == 'No' or z == 'no':
                    print 'Returing to main menu'

                else:
                    print 'Returning to main menu'

            except:
                print traceback.print_exc()
                print 'Download failed'
                pass
        elif x == 'No' or 'no':
            print 'Not downloading'
        else:
            print 'Please answer Yes or No'


    @staticmethod
    def writelog(msg):
        logging.info(msg)

    def getfeed(self):
        return self.iplist
    def replacefeed(self, newlist):
        self.iplist = []
        self.iplist = newlist

    def addtofeed(self, ip):
        self.iplist.append(ip)

    def clearfeed(self):
        self.iplist = []

    def deleteinfeed(self, ip):
        self.iplist.remove(ip)

    def getknown(self):
        return self.known

    #TODO: Add support for Combine type data
    def parsefeed(self):
        thedir = self.feeddir + '/*.txt'
        iplists = glob.glob(thedir)
        for iplist in iplists:
            try:
                with open(iplist) as ipfile:
                    for line in ipfile:
                        line = line.rstrip('\n')
                        self.iplist.append(line)
            except:
                self.writelog('IP list error. Please check ip list file '+iplist)
                exit()
        if self.getsize() > 0:
            self.writelog('IP list loaded. Total size: '+str(self.getsize()))


    def getsize(self):
        return len(self.iplist)

    def checkinlist(self, ipaddr):
        ip = IP(ipaddr)
        if ip.iptype() == 'PRIVATE':
            return False
        elif ipaddr in self.iplist:
            return True
        else:
            pass
            return False

