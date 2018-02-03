from config import config
import pymongo
from pymongo import MongoClient
import dpkt
import logging
import traceback
from datetime import *
from bson.objectid import ObjectId
import os

class dbhandler:

    def __init__(self):
        try:
            cfg = config()
            dbhost = cfg.getdbhost()
            dbport = int(cfg.getdbport())
            self.client = MongoClient(dbhost, dbport)
        except:
            print 'DB Error. Is mongodb installed and running?'
            self.writelog("DB Error. Is mongodb installed and running?")
            os._exit(0)

    @staticmethod
    def writelog(msg):
        logging.info(msg)

    def getAlertCollection(self):
        db = self.client.tinyids
        self.collection_alerts = db.alerts
        return self.collection_alerts

    def getExcludeTrafficCollection(self):
        db = self.client.tinyids
        self.collection_extraffic = db.excluded_traffic
        return self.collection_extraffic

    def getFilterCollection(self):
        db = self.client.tinyids
        self.collection_filters = db.filters
        return self.collection_filters

    def getThreatURLCollection(self):
        db = self.client.tinyids
        self.collection_threaturl = db.threat_urls
        return  self.collection_threaturl

    def addThreatUrl(self, url, desc):
        collection = self.getThreatURLCollection()
        post = { 'date' : datetime.utcnow(), 'url' : url, 'description' : desc }
        collection.insert(post)

    #Malicious commiunication alert
    def addmalcomalert(self, ip, sourceip, destip, srcport, dstport):
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            collection = self.getAlertCollection()
            post = { 'date' : datetime.utcnow(), "type" : 1, "proto" : 17 , "srcip" : sourceip, "dstip" : destip, "dstport" : int(dstport), "srcport" : int(srcport) }
            _id = collection.insert(post)
            return str(_id)
        elif ip.p == dpkt.ip.IP_PROTO_TCP:
            collection = self.getAlertCollection()
            post = { 'date' : datetime.utcnow(), "type" : 1, "proto" : 6 , "srcip" : sourceip, "dstip" : destip, "dstport" : int(dstport), "srcport" : int(srcport) }
            _id = collection.insert(post)
            return str(_id)
        else:
            collection = self.getAlertCollection()
            post = { 'date' : datetime.utcnow(), "type" : 1, "proto" : 255 , "srcip" : sourceip, "dstip" : destip, "dstport" : int(dstport), "srcport" : int(srcport) }
            _id = collection.insert(post)
            return str(_id)

    #Standard IDS alert
    def addalert(self, ip, ruleid, ruledesc, triggerdata, sourceip, destip, srcport, dstport):
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            collection = self.getAlertCollection()
            post = { 'date' : datetime.utcnow(), "type" : 2, "proto" : 17 , "srcip" : sourceip, "dstip" : destip, "dstport" : int(dstport), "srcport" : int(srcport), "ruleid" : ruleid, "ruledesc" : ruledesc, "triggerdata" : triggerdata}
            _id = collection.insert(post)
            return str(_id)
        elif ip.p == dpkt.ip.IP_PROTO_TCP:
            collection = self.getAlertCollection()
            post = { 'date' : datetime.utcnow(), "type" : 2, "proto" : 6 , "srcip" : sourceip, "dstip" : destip, "dstport" : int(dstport), "srcport" : int(srcport), "ruleid" : ruleid, "ruledesc" : ruledesc, "triggerdata" : triggerdata}
            _id = collection.insert(post)
            return str(_id)
        else:
            collection = self.getAlertCollection()
            post = { 'date' : datetime.utcnow(), "type" : 2, "proto" : 255 , "srcip" : sourceip, "dstip" : destip, "dstport" : int(dstport), "srcport" : int(srcport), "ruleid" : ruleid, "ruledesc" : ruledesc, "triggerdata" : triggerdata}
            _id = collection.insert(post)
            return str(_id)


    def getalerts(self,amount):
        collection = self.getAlertCollection()
        alerts = []
        if not amount:
            for data in collection.find().limit(10):
                if data["type"] == 2:
                    alerts.append( { "id" : str(data["_id"]), "type" : data["type"], "date" : data["date"] , "rule_id" : data["ruleid"], "rule_desc" : data["ruledesc"], "triggerdata" : data["triggerdata"] , "srcip" : data["srcip"] , "srcport" : data["srcport"],  "dstip" : data["dstip"], "dstport" : data["dstport"] } )
                else:
                    alerts.append( { "id" : str(data["_id"]),  "type" : data["type"], "date" : data["date"] , "srcip" : data["srcip"] , "srcport" : data["srcport"],  "dstip" : data["dstip"], "dstport" : data["dstport"] } )
        else:
            for data in collection.find():
                if data["type"] == 2:
                    alerts.append(  { "id" : str(data["_id"]), "type" : data["type"], "date" : data["date"] , "rule_id" : data["ruleid"], "rule_desc" : data["ruledesc"], "triggerdata" : data["triggerdata"] , "srcip" : data["srcip"] , "srcport" : data["srcport"],  "dstip" : data["dstip"], "dstport" : data["dstport"] } )
                else:
                    alerts.append( { "id" : str(data["_id"]),  "type" : data["type"],"date" : data["date"] , "srcip" : data["srcip"] , "srcport" : data["srcport"],  "dstip" : data["dstip"], "dstport" : data["dstport"] } )
        return alerts

    def getalert(self, idnr):
	try:
	        collection = self.getAlertCollection()
       		id = ObjectId(idnr)
        	alert = collection.find( { '_id' : { '$eq' : id } } )
        	return alert
	except:
		return []
		pass

    def addfilter(self,sourceip, destip, sport, dport, sig_id):
        collection = self.getFilterCollection()
        post = { 'srcip' : sourceip, 'srcport' : sport, 'dstip' : destip, 'dstport' : dport, 'rule_id' : sig_id }
        collection.insert(post)

    def getfilters(self):
        fil = []
        collection = self.getFilterCollection()
        filters = collection.find()
        for thefilter in filters:
            fil.append(  { '_id' : thefilter["_id"], 'srcip' : thefilter["srcip"], 'srcport' : thefilter["srcport"], 'dstip' : thefilter["dstip"], 'dstport' : thefilter["dstport"], 'rule_id' : thefilter["rule_id"] } )

        return fil

    def delfilter(self, filterid):
        collection = self.getFilterCollection()
        idnr = ObjectId(filterid)
        collection.remove({"_id": idnr })

    def getexclusions(self, proto):
        #Default rules to exclude HTTPS and SSH traffic.
        #db.excluded_traffic.insert( { 'date' : new ISODate(), "proto" : 17 , port : 22 } )
        #db.excluded_traffic.insert( { 'date' : new ISODate(), "proto" : 17 , port : 443 } )
        collection = self.getExcludeTrafficCollection()
        exclude = collection.find( { 'proto' : { "$eq" : proto } } )
        return exclude
