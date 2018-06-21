import struct

import packet

from collections import OrderedDict
import time
import message
import request

# Routing class to keep track for Closest node in the network
class Routing:

    def __init__(self, STS, k=4):
        self.RoutingTable = OrderedDict()
        self.ownID = packet.xxhashUser('netsec41')
        self.k = k
        self.STS = STS

    def GetRouteTable(self):
        # self.RoutingTable = OrderedDict(self.RoutingTable)
        return self.RoutingTable

    def SetRouteTable(self, data):
        self.RoutingTable = data

    # insert bootstrap into the routing table
    def insertBootstrap(self):
        templist = []
        records = {}
        templist.append(struct.pack('B', 172) + struct.pack('B', 18) + struct.pack('B', 0) + struct.pack('B', 252))
        templist.append(1337)
        templist.append(int(0xffff))
        templist.append(str(format(int(0xffff), '016b')))
        templist.append(time.time())
        records[str(format(0xffff, '016b'))] = templist
        self.BuildTable(records)

    # Build up the routing table entries
    def PopulateRoutingTable(self, data):
        # packet.hex_print(data)
        length = struct.unpack('>i', data[13:17])[0]
        ip_data = data[17: length + 17]
        # ip_data = data[17:]
        records = {}
        while ip_data:
            templist = []
            if ip_data[0] == 4:

                final_ip = str(ip_data[1]) + '.' + str(ip_data[2]) + '.' + str(ip_data[3]) + '.' + str(ip_data[4])
                ip = ip_data[1:5]
                # port = int.from_bytes(ip_data[5:7], byteorder='big')
                port = struct.unpack('>H', ip_data[5:7])[0]
                length = struct.unpack('>I', ip_data[7:11])[0]
                node_id = struct.unpack('>H', ip_data[11: length + 11])[0]
                # if node_id == self.ownID or not self.pingCheck(sock, final_ip, port):
                if node_id == self.ownID:
                    ip_data = ip_data[13:]
                    continue
                templist.append(ip)
                templist.append(port)
                templist.append(node_id)
                templist.append(str(format(node_id, '016b')))
                records[str(format(node_id, '016b'))] = templist

                ip_data = ip_data[13:]

            elif ip_data[0] == 6:
                ip_data = ip_data[25:]
                continue

            else:
                break
        return records

    # spilt bucket and keep track of the most recently contacted nodes
    def splitBucket(self, key, bucket):
        length = len(key)
        splitBucket = {}
        left = []
        right = []
        if key == 'I':
            for i in bucket:
                j = i[3]
                if j[0] == '0':
                    left.append(i)
                else:
                    right.append(i)
        else:
            for i in bucket:
                j = i[3]
                if j[0:length + 1] == key + '0':
                    left.append(i)
                else:
                    right.append(i)

        if key == 'I':
            splitBucket['0'] = left
            splitBucket['1'] = right
        else:
            splitBucket[key + '0'] = left
            splitBucket[key + '1'] = right

        return splitBucket

    # check if the node is alive based on PING message
    def pingCheck(self, IP, port):
        nonce = request.KademliaProtocol(self.STS).ping((IP, port))
        time.sleep(3)
        result = message.Messages().returnResponse(nonce)
        message.Messages().removeRequest(nonce)
        return result

    # get the alive nodes in the bucket
    def getAliveNodes(self, nodeTuple):
        LRU = nodeTuple[0]
        index = nodeTuple.index(LRU)
        for node in nodeTuple:
            if node[4] < LRU[4]:
                LRU = node
                index = nodeTuple.index(LRU)
        if self.pingCheck(packet.constructIP(LRU[0]), LRU[1]):
            LRU[4] = time.time()
            nodeTuple.pop(index)
            nodeTuple.append(LRU)
        else:
            nodeTuple.pop(index)

        return nodeTuple

    # build the routing table
    def BuildTable(self, records):
        for r, rv in records.items():
            if not self.RoutingTable:
                val = []
                val.append(rv)
                self.RoutingTable['I'] = val
                continue
            if len(self.RoutingTable) == 1:
                if len(self.RoutingTable['I']) >= self.k:
                    # IGNORE PING-CHECK for first split
                    temp_bucket = self.splitBucket('I', self.RoutingTable['I'])
                    self.RoutingTable.pop('I', None)
                    for k, v in temp_bucket.items():
                        self.RoutingTable[k] = v
                        continue
                else:
                    v = self.RoutingTable.pop('I')
                    v.append(rv)
                    self.RoutingTable['I'] = v
                    continue

            for keys in self.RoutingTable:
                if r.startswith(keys):
                    key_matched = keys
                    if rv in self.RoutingTable[keys]:
                        continue
                    if len(self.RoutingTable[key_matched]) >= self.k:
                        # PING-CHECK for LEAST RECENTLY USED
                        if str(format(self.ownID, '016b')).startswith(key_matched):
                            temp_bucket = self.splitBucket(keys, self.RoutingTable[key_matched])
                            self.RoutingTable.pop(keys, None)
                            for k, v in temp_bucket.items():
                                self.RoutingTable[k] = v
                                if r.startswith(k):
                                    self.RoutingTable[k].append(rv)
                            break
                        else:
                            if len(self.getAliveNodes(self.RoutingTable[key_matched])) < self.k:
                                self.RoutingTable[key_matched] = self.getAliveNodes(self.RoutingTable[key_matched])
                                self.RoutingTable[key_matched].append(rv)
                            else:
                                self.RoutingTable[key_matched] = self.getAliveNodes(self.RoutingTable[key_matched])

                    elif key_matched:
                        v = self.RoutingTable.pop(key_matched)
                        v.append(rv)
                        self.RoutingTable[keys] = v
                        break

    # find the K-closest nodes
    def findClosest(self, node, Kbuckets, KcloseNodes):
        if len(node) == 0 or len(KcloseNodes) >= self.k:
            return KcloseNodes

        for key, v in Kbuckets.items():

            if key.startswith(node):
                keySelected = key
                for val in v:
                    if val and val not in KcloseNodes:
                        KcloseNodes.append(val)
                        if len(KcloseNodes) >= self.k:
                            return KcloseNodes

        if len(KcloseNodes) < self.k:
            KcloseNodes = self.findClosest(node[0:len(node) - 1], Kbuckets, KcloseNodes)

        return KcloseNodes

    # find the K-closest nodes
    def Kclosest(self, nodeID):
        Kbuckets = self.GetRouteTable()
        KcloseNodes = []
        keySelected = None
        keySelf = format(packet.xxhashUser('netsec41'), '016b')
        node = format(nodeID, '016b')

        for key, v in Kbuckets.items():

            if node.startswith(key):
                keySelected = key
                for val in v:
                    if val and val not in KcloseNodes:
                        KcloseNodes.append(val)
                        if len(KcloseNodes) >= self.k:
                            return KcloseNodes

        if not keySelected:
            for _, v in Kbuckets.items():
                for val in v:
                    if val and val not in KcloseNodes:
                        KcloseNodes.append(val)
                        if len(KcloseNodes) >= self.k:
                            return KcloseNodes

        else:
            KcloseNodes = self.findClosest(keySelected[0:len(keySelected) - 1], Kbuckets, KcloseNodes)
            if KcloseNodes == self.k:
                return KcloseNodes
            else:
                for _, v in Kbuckets.items():
                    for val in v:
                        if val and val not in KcloseNodes:
                            KcloseNodes.append(val)
                            if len(KcloseNodes) >= self.k:
                                return KcloseNodes
        return KcloseNodes