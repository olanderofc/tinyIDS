from IPy import IP
from tabulate import tabulate
from dbhandler import dbhandler

import logging
import time
import logging.handlers
import json
import base64
import os


class commander:
    def __init__(self, LOG_FILENAME):
        print "=================================================="
        print "Welcome to tinyIDS by David Olander."
        print "Type 'help' for a list of commands"
        print "=================================================="
        self.logfile = LOG_FILENAME
        self.dbhand = dbhandler()

    @staticmethod
    def gettime():
        t = time.localtime()
        return "%s " % time.asctime(t)

    @staticmethod
    def writelog(msg):
        logging.info("Command '" + msg + "' issued")

    @staticmethod
    def printrules(rules):
        headers = ["ID", "Name", "Enabled", "Filename", "Regexp"]
        values = []
        for rule in rules:
            data = [str(rule["rule_id"]), rule["rule_name"], rule["enabled"], rule["file_name"], rule["regexp"]]
            values.append(data)

        print tabulate(values, headers, stralign='left', numalign='left')

    @staticmethod
    def setrulestate(ruleid, rules, state):
        success = False
        for rule in rules:
            if str(rule["rule_id"]) == ruleid:
                if state is False:
                    print rule["rule_name"] + " is now set to disabled"
                    rule["enabled"] = "no"
                else:
                    print rule["rule_name"] + " is now set to enabled"
                    rule["enabled"] = "yes"
                success = True
                break

        if not success:
            print "Unable to change rule state. Correct rule id?"

    @staticmethod
    def saverulestate(rules):
        for rule in rules:
            f = open(rule["file_name"], 'w')
            data = json.dumps(rule, sort_keys=True, indent=4)
            f.write(data)
            f.close()

    @staticmethod
    def showhelp():
        print "tinyIDS CLI"
        print "A small, but flexible IDS. Keeping you paranoid since 2014."
        print "==========================================================="
        headers = ["Command", "Description"]
        data = [['list known ip', 'List all known IPs in cache'],
                ['stat known ip', 'Show number of known IPs in cache'], ['stat ports', 'List statistics per port'],
                ['show log', 'Show log file'], ['show alerts', 'Show all IDS alerts in the log file'],
                ['show alert <id>', 'Show information regarding a specific alert id'],
                ['show threats', 'Show all threat feed alerts in the log file'], ['show rules', 'List all rules'],
                ['disable rule', 'Disable a rule'], ['enable rule <id>', 'Enable a rule'],
                ['show filters', 'Show filters'], ['add filter', 'Add filter'], ['del filter', 'Delete a filter'],
                ['mod filter', 'Modify a filter'], ['add threat url', 'Add a url to auto download'],
                ['del threat url', 'Delete a auto download url'],
                ['list threat urls', 'Show urls that are being auto downloaded'],
                ['list threat ip', 'List all IPs in threat list'],
                ['stat threat ip', 'Show number of IPs in threat list'],
                ['clear threat list', 'Clear the threat ip list'], ['search threat ip', 'Search for IP in threat list'],
                ['add threat ip', 'Add new IP to threat list'], ['del threat ip', 'Delete IP in threat list'],
                ['dl threat list', 'Download threat list'],
                ['set update time', 'Change the update time of the feed updates'],
                ['get update time', 'View the current update time'], ['date', 'Show current time'],
                ['clear log', 'Clear tinyids.log file'], ['quit/exit', 'Quit tinyIDS']]
        print tabulate(data, headers)
        print "=================================================="

    def quitapp(self, rules):
        print "Saving state and quitting.."
        self.saverulestate(rules)
        os._exit(0)

    def menu(self, feeds, rules, stats, filt, update):
        while True:
            x = raw_input('> ')
            if x == "help":
                self.writelog(x)
                self.showhelp()

            elif x == "quit" or x == "exit":
                self.writelog(x)
                self.quitapp(rules)
            elif x == "date":
                print self.gettime()
            elif x == "clear log":
                open(self.logfile, 'w').close()
            elif x == "add threat url":
                url = raw_input("Enter URL: ")
                desc = raw_input("Enter description: ")
                print "Are you sure you want to add " + url + " ( " + desc + " )"
                ans = raw_input("y/n: ")
                if ans.lower() == 'y':
                    feeds.addurltolist(url, desc)
                    self.dbhand.addThreatUrl(url, desc)
                    print "The url " + url + " was added to auto download list"
                else:
                    print 'Aborted'
                    continue

            elif x == "list threat urls":
                headers = ["URL", "Description"]
                values = []
                for url in feeds.getthreaturls():
                    data = [url[0], url[1]]
                    values.append(data)

                print tabulate(values, headers, stralign='left', numalign='left')


            elif x == "list threat ip":
                self.writelog(x)
                ipfeed = feeds.getfeed()
                for ip in ipfeed:
                    print ip

                print "Number of IP's in current threat list: " + str(len(ipfeed))
            elif x == "stat threat ip":
                self.writelog(x)
                print "Number of IP's in current threat list: " + str(len(feeds.getfeed()))

            elif x == "show rules":
                self.writelog(x)
                self.printrules(rules)
            elif x == 'disable rule':
                self.printrules(rules)
                rid = raw_input('Enter rule id: ')
                self.setrulestate(rid, rules, False)
                self.printrules(rules)
            elif 'enable rule' in x:
                idval = x.split(' ')
                if len(idval) == 3:
                    self.printrules(rules)
                    rid = idval[2]
                    self.setrulestate(rid, rules, True)
                    self.printrules(rules)

            elif x == "stat known ip":
                self.writelog("Command stat knownip issued")
                tmp = feeds.getknown()
                print str(len(tmp))

            elif x == "list known ip":
                self.writelog(x)
                tmp = feeds.getknown()
                for ip in tmp:
                    print ip
            elif x == "stat ports":
                self.writelog(x)
                stats.showdestport()
                stats.showdsrcport()
            elif x == "show log":
                self.writelog(x)
                filename = open("tinyids.log")
                for line in filename:
                    line = line.replace('\n', '')
                    print line

            elif x == "show alerts":
                headers = ["Date ", "ID", "Rule ID", "Rule Name", "Source IP", "Source Port", "Destination IP",
                           "Destination Port"]
                alerts = self.dbhand.getalerts(10)
                values = []
                for alert in alerts:
                    data = []
                    if alert['type'] == 1:
                        data.append(alert["date"])
                        data.append(alert["id"])
                        data.append("N/A")
                        data.append("Malicious Communication")
                        data.append(alert["srcip"])
                        data.append(alert["srcport"])
                        data.append(alert["dstip"])
                        data.append(alert["dstport"])
                    else:
                        data.append(alert["date"])
                        data.append(alert["id"])
                        data.append(alert["rule_id"])
                        data.append(alert["rule_desc"])
                        data.append(alert["srcip"])
                        data.append(alert["srcport"])
                        data.append(alert["dstip"])
                        data.append(alert["dstport"])
                    values.append(data)
                print tabulate(values, headers, stralign='left', numalign='left')

            elif "show alert" in x:
                idval = x.split(' ')
                if len(idval) == 3:
                    alert = self.dbhand.getalert(idval[2])
                    for data in alert:
                        if data['type'] == 2:
                            print "ID: ", idval[2]
                            print "Source IP: ", data["srcip"]
                            print "Source Port: ", data["srcport"]
                            print "Destination IP: ", data["dstip"]
                            print "Destination Port: ", data["dstport"]
                            print "Protocol: ", data["proto"]
                            print "Rule name: ", data["ruledesc"]
                            print "----------------------------------"
                            print "Triggerdata base64: "
                            print
                            print data["triggerdata"]
                            print "----------------------------------"
                            print "Triggerdata decoded: "
                            print
                            print base64.b64decode(data["triggerdata"])
                            print "----------------------------------"
                        else:
                            print 'No detailed data available'
                else:
                    print 'Printing alert details require mongodb id'

            elif x == "show threats":
                self.writelog(x)
                filename = open("tinyids.log")
                for line in filename:
                    if "[Threat Alert]" in line:
                        print line

            elif x == "search threat ip":
                self.writelog(x)
                y = raw_input('Enter IP: ')
                try:
                    ip = IP(y)
                    ipfeed = feeds.getfeed()
                    if y in ipfeed:
                        print 'Found'
                    else:
                        print 'Not found'
                except:
                    print 'Unable to search for that.'
                    continue

            elif x == 'add threat ip':
                self.writelog(x)
                y = raw_input('Enter IP: ')
                try:
                    ip = IP(y)
                    if ip.iptype() != 'PRIVATE':
                        feeds.addtofeed(y)
                        self.writelog("IP " + y + " added to threat list")
                    else:
                        print 'IP is private. Not added'
                        continue
                except:
                    print 'Unable to add. Is the IP correct?'
                    continue

            elif x == 'del threat ip':
                self.writelog(x)
                y = raw_input('Enter IP: ')
                try:
                    ip = IP(y)
                    feeds.deleteinfeed(y)
                    self.writelog("IP " + y + " removed from threat list")
                except:
                    print 'Unable to delete. Is the IP correct?'
                    continue
            elif x == 'dl threat list':
                self.writelog(x)
                y = raw_input('Enter URL: ')
                feeds.download(y)
            elif x == 'set update time':
                print 'Current update time is set to ', str(update.gettime())
                y = raw_input('Enter new time: ')
                try:
                    thetime = float(y)
                except:
                    print 'Invalid format. Please input integer'
                else:
                    print 'Update time has been changed'
                    update.changetime(thetime)

            elif x == 'get update time':
                print 'Current update time is set to ', str(update.gettime())

            elif x == 'clear threat list':
                self.writelog(x)
                feeds.clearfeed()
            elif x == 'show filters':
                print filt
            elif x == 'add filter':
                self.printrules(rules)
                rid = raw_input('Rule ID: ')
                sip = raw_input('Source IP: ')
                dip = raw_input('Destination IP: ')
                sport = raw_input('Source port: ')
                dport = raw_input('Destination port: ')
                filt.validate(sip, dip, sport, dport, rid)
                filt.getfilters()
            elif x == 'del filter':
                filt.getfilters()
                fid = raw_input('Enter filter ID to remove: ')
                filt.delfilter(fid)
                print filt
            elif x == '':
                print '>'
            else:
                print "Unknown command. Type 'help' for list of commands"
