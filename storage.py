import time

from collections import OrderedDict

# manage store operations
class Storage:
    # set Time-to-live as 5 minutes
    def __init__(self, ttl=300):
        self.ttl = ttl
        self.data = OrderedDict()

    # set the data based on the hash-key
    def setData(self, hashKey, value):
        self.expireCache()
        if hashKey in self.data:
            value = self.data[hashKey][0]
        self.data[hashKey] = (value, time.time())

    # return the data associated with the hash-key
    def getData(self, hashKey):
        self.expireCache()
        if hashKey in self.data:
            value = self.data[hashKey][0]
            self.data[hashKey] = (value, time.time())
            return value
        else:
            return None

    # return the list of expired data based on TTL
    def expiredData(self, age):
        lastUsedTime = time.time() - age
        expiredList = []
        for keys in self.data:
            if lastUsedTime >= self.data[keys][1]:
                expiredList.append(keys)
        return expiredList

    # delete the expired data
    def expireCache(self):
        for hashKey in self.expiredData(self.ttl):
            self.data.pop(hashKey)

    # return currently available data
    def getItems(self):
        self.expireCache()
        return self.data