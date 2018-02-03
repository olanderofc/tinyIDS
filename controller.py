import psutil
import logging
import time
from config import config

class controller:

    def __init__(self):
        self.memcount = 0
        self.cpucount = 0

        self.CRITICAL = 95
        self.HIGH = 90
        self.MEDIUM = 80

        self.cfg = config()
        self.BUFFERSIZE = self.cfg.gettrafficbuffer()
        self.DEBUG = self.cfg.getdebug()

    @staticmethod
    def writelog(msg):
        logging.info(msg)

    def cpuusage(self):
        count = 0
        usage = psutil.cpu_percent(interval=1, percpu=True)
        for cpu in usage:
            if cpu > self.CRITICAL:
                self.writelog("Warning. CPU "+str(count)+" Usage over "+str(self.CRITICAL)+"%")
                self.cpucount += 1
            elif self.HIGH < cpu < self.CRITICAL:
                self.writelog("Warning. CPU "+str(count)+" Usage over "+str(self.HIGH)+"%")
                self.cpucount += 1
            elif self.MEDIUM < cpu < self.HIGH:
                self.writelog("Warning. CPU "+str(count)+" Usage over "+str(self.CRITICAL)+"%")
                self.cpucount += 1
            else:
                self.cpucount = 0
            count += 1

        if self.cpucount > 1:
            return True
        else:
            return False

    def memoryusage(self):
        mem = psutil.virtual_memory()
        if mem.percent >= self.CRITICAL:
            self.writelog("Warning. Memory usage at above "+str(self.CRITICAL)+"%")
            self.memcount += 1
        elif self.HIGH < mem.percent < self.CRITICAL:
            self.writelog("Warning. Memory usage at above "+str(self.HIGH)+"%")
            self.memcount += 1
        elif self.MEDIUM < mem.percent < self.HIGH:
            self.writelog("Warning. Memory usage at above "+str(self.MEDIUM)+"%")
            self.memcount += 1
        else:
            self.memcount = 0

        if self.memcount > 0:
            return True
        else:
            return False

    def handle(self, inspectionq, maliciousq, packetlogq):
        self.writelog("Buffer set to "+str(self.BUFFERSIZE))
        while True:
            if self.DEBUG:
                self.writelog("Inspection Queue Size: "+str(inspectionq.qsize()))
                self.writelog("Malicious Connection Queue Size: "+str(maliciousq.qsize()))
                self.writelog("Packetlog Queue Size: "+str(packetlogq.qsize()))

            if self.memoryusage():
                self.writelog("Inspection Queue Size: "+str(inspectionq.qsize()))
                self.writelog("Malicious Connection Queue Size: "+str(maliciousq.qsize()))
                self.writelog("Packetlog Queue Size: "+str(packetlogq.qsize()))

            if self.cpuusage():
                self.writelog("Inspection Queue Size: "+str(inspectionq.qsize()))
                self.writelog("Malicious Connection Queue Size: "+str(maliciousq.qsize()))
                self.writelog("Packetlog Queue Size: "+str(packetlogq.qsize()))

            time.sleep(1)



