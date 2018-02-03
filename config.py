import ConfigParser
import traceback
import os
import logging

class config:
    def __init__(self):
        try:
            cfglocation =  os.path.dirname(os.path.realpath(__file__))
            self.config = ConfigParser.RawConfigParser()
            self.config.read(cfglocation + '/settings/tinyids.cfg')
        except:
            print traceback.print_exc()
            print 'Unable to read config file'
            os._exit(0)

    @staticmethod
    def writelog(msg):
        logging.info(msg)

    def getfeeddir(self):
        return self.config.get("tinyids", "feeddir")

    def getruledir(self):
        return self.config.get("tinyids", "ruledir")

    def getpcapdir(self):
        return self.config.get("tinyids", "pcapdir")

    def getlogfile(self):
        return self.config.get("tinyids", "logfile")

    def getfeedtime(self):
        return self.config.get("tinyids", "feedupdate")

    def getinterface(self):
        return self.config.get("tinyids", "captureifc")

    def getfilters(self):
        return self.config.get("tinyids", "filters")

    def gettrafficbuffer(self):
        try:
            return int(self.config.get("tinyids", "trafficbuffer"))
        except:
            self.writelog("Value fo traffic buffer is not an integer value")
            os._exit(0)

    def getdebug(self):
        debug = self.config.get("tinyids", "debug")
        if debug == "True":
            return True
        elif debug == "False":
            return False
        else:
            return False

    def getvtapikey(self):
        return self.config.get("virustotal", "apikey")

    def getvtcpm(self):
        return self.config.get("virustotal", "cpm")

    def getdbhost(self):
        return self.config.get("mongodb", "server")

    def getdbport(self):
        return self.config.get("mongodb", "port")

