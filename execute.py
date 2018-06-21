#! /usr/bin/python3.4
import socket
from threading import Thread
import packet
import request
import storage
import routing
import message
from collections import OrderedDict
import time
import base64
import sts_checks
import sts_utility
import struct
import pysodium

localIP = '0.0.0.0'
localPort = 1337
cSuite = 1
endpoint_address = ('172.18.0.252', 3333)

# create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((localIP, localPort))

# fetch certificate and its status
myCert, myCertStatus = sts_utility.decodeMyCertificate(sock, endpoint_address)
# create an STS (TLS) instance
STS = sts_checks.STS(sock, myCert, myCertStatus)
# create a routing table instance
RT = routing.Routing(STS)
# insert bootstrap node to routing table
RT.insertBootstrap()
# for storing all the recursive nodes in the recursive lookup
recursiveNodes = OrderedDict()
# storage instance
StoreData = storage.Storage()

def packetLengthCheck(data):
    return len(data) >= 13

# check the message validity based on the nonce and insert into message queue
def messageCheck(data):
    if message.Messages().checkResponse(packet.nonceExtract(data)):
        message.Messages().insertResponse(packet.nonceExtract(data), data)
        return True
    return False

# remove the message from message queue
def messageRemove(data):
    message.Messages().removeRequest(packet.nonceExtract(data))

# update the routing table based on K-closest nodes
def updateRouteTable(data, addr):
    record = OrderedDict()
    ownID = str(format(packet.unpackNodeID(data), '016b'))
    nodes = RT.Kclosest(packet.unpackNodeID(data))
    for nodeID in nodes:
        if nodeID[3] == ownID:
            return
    record[ownID] = [packet.deconstructIP(addr[0]), addr[1], packet.unpackNodeID(data), ownID, time.time()]
    RT.BuildTable(record)
    # pprint.pprint(RT.GetRouteTable())

# server logic
def serverProtocol(STS):
    global cSuite

    while True:
        data, addr = STS.receive()
        if data == None or addr == None:
            continue

        # CHECK FOR THE MIN-PACKET LENGTH

        if not packetLengthCheck(data) or len(addr) > 15:
            # response = packet.errorResponse(data)
            response = 'WRONG PACKET FORMAT'.encode('utf-8')
            print('Send %r to %s' % (response, addr))
            # sock.sendto(response, addr)
            STS.send(addr, cSuite, response)

        # REQUESTS RECEIVED

        # PING REQUEST
        elif data[0] == 0:
            print('=== PING RECEIVED ===')
            response = packet.pingResponse(data)
            print('Send %r to %s' % (response, addr))
            # sock.sendto(response, addr)
            STS.send(addr, cSuite, response)
            updateRouteTable(data, addr)

        # STORE REQUEST
        elif data[0] == 2:
            # TO-DO STORE DATA
            print('=== STORE RECEIVED ===')
            packet.hex_print(data)
            storeNewData = packet.unpackReceivedData(data)
            if storeNewData:
                key = packet.hashData(storeNewData)
                StoreData.setData(key, storeNewData)
                response = packet.basic_protocol_response(3, data)
                # sock.sendto(response, addr)
                STS.send(addr, cSuite, response)
                updateRouteTable(data, addr)
                response = packet.storeResponse(data)
                print('Send %r to %s' % (response, addr))

        # FIND NODE REQUEST
        elif data[0] == 4:
            #TO-DO ADD NODE TO TABLE WHEN FIND-NODE RECEIVED
            print('=== FIND NODE RECEIVED ===')
            print('Receive %r to %s' % (data, addr))
            # pprint.pprint(RT.GetRouteTable())
            nodeID = packet.unpackReceivedInt(data)
            lookup = RT.Kclosest(nodeID)
            response = packet.findNodeResponse(data, lookup)
            # packet.hex_print(response)
            print('Send %r to %s' % (response, addr))
            # sock.sendto(response, addr)
            STS.send(addr, cSuite, response)
            updateRouteTable(data, addr)

        # FIND VALUE REQUEST:
        elif data[0] == 6:
            print('=== FIND VALUE RECEIVED ===')
            print('Receive %r to %s' % (data, addr))
            value = packet.unpackReceivedInt(data)
            if StoreData.getData(value):
                response = packet.findValueResponseData(data, StoreData.getData(value))
            else:
                lookup = RT.Kclosest(value)
                # print(lookup)
                response = packet.findValueResponseNode(data, lookup)
            print('Send %r to %s' % (response, addr))
            # sock.sendto(response, addr)
            STS.send(addr, cSuite, response)
            updateRouteTable(data, addr)

        # ERROR Response
        elif data[0] == 8:
            print('ERROR Packet received')
            print('Receive %r to %s' % (data, addr))

        # REPLIES RECEIVED

        # PING ACK RECEIVE
        elif data[0] == 1:
            print('PING-RESPONSE RECEIVED')
            print('Receive %r to %s' % (data, addr))
            messageCheck(data)
            # packet.hex_print(data)

        # STORE ACK RECEIVE
        elif data[0] == 3:
            print('STORE ACK RECEIVED')
            print('Receive %r to %s' % (data, addr))

        # FIND-NODE ACK RECEIVE
        elif data[0] == 5:
            print('FIND-NODE ACK')
            print('Receive %r to %s' % (data, addr))
            messageCheck(data)

        # FIND-VALUE ACK RECEIVE
        elif data[0] == 7:
            print('FIND-VALUE ACK')
            print('Receive %r to %s' % (data, addr))
            packet.hex_print(data)

        else:
            response = packet.errorResponse(data)
            print('Send %r to %s' % (response, addr))
            # sock.sendto(response, addr)
            STS.send(addr, cSuite, response)

# recursive lookup based on K-closest nodes from our ID
def recursiveLookup(STS, nodeTuple):
    global recursiveNodes
    results = request.KademliaProtocol(STS).findNode(packet.xxhashUser('netsec41'),
                                                  (packet.constructIP(nodeTuple[0]), nodeTuple[1]))
    time.sleep(3)
    nodeData = message.Messages().returnResponse(results)
    if nodeData is not None:
        message.Messages().removeRequest(results)
        for key, value in RT.PopulateRoutingTable(nodeData).items():
            recursiveNodes[key] = value
    else:
        message.Messages().removeRequest(results)
    # return

# initial lookup based on our own id
def selfLookup(STS, threads_inner, result):
    global recursiveNodes
    time.sleep(3)
    nodeData = message.Messages().returnResponse(result)

    tempNodes = OrderedDict()
    if nodeData is not None:
        message.Messages().removeRequest(result)
        recursiveNodes = RT.PopulateRoutingTable(nodeData)
        final = False
        while not final:
            for key, value in recursiveNodes.items():
                tempNodes[key] = value
            for _, nodeTuple in tempNodes.items():
                t = Thread(target=recursiveLookup, args=[STS, nodeTuple])
                threads_inner.append(t)
                t.start()
            for t1 in threads_inner:
                t1.join()
            if recursiveNodes == tempNodes:
                final = True

        for _, values in recursiveNodes.items():
            values.append(time.time())

        RT.BuildTable(recursiveNodes)

    else:
        message.Messages().removeRequest(result)

# store the data on the nodes
def storeOnNodes(STS):
    global StoreData
    while True:
        file = open("/home/netsec41/dht_data", "r")
        StoreData.expireCache()
        for line in file:
            data = base64.b64decode(line.strip())
            key = packet.hashData(data)
            kClosestNodes = RT.Kclosest(key)
            for nodeTuple in kClosestNodes:
                server = packet.constructIP(nodeTuple[0])
                port = nodeTuple[1]
                result = request.KademliaProtocol(STS).store(data, (server, port))
                message.Messages().removeRequest(result)
        file.close()
        STS.cleanConnectionStates()
        time.sleep(300)

# update current certificate's status
def updateCertificateStatus(STS):
    global myCert, sock, endpoint_address
    while True:
        myCertStatus = STS.getCertificateStatus()
        status_tuple,_ = sts_utility.certificateStatusDict(myCertStatus)
        # print(status_tuple)
        currTime = int(time.time())
        validity = status_tuple['F'] + status_tuple['U']
        self_cert = pysodium.crypto_generichash(myCert, outlen=64)
        msg = struct.pack('>I', len(self_cert)) + self_cert
        if validity < currTime:
            sock.sendto(msg, endpoint_address)
            time.sleep(5)
        elif (validity - currTime) >= 0:
            time.sleep(validity - currTime)
            sock.sendto(msg, endpoint_address)

if __name__ == '__main__':
    try:
        threads = []
        threads_inner = []

        print('=== DHT NODE STARTED ON ' + localIP + ':' + str(localPort) + ' ===')

        # start the server thread
        th1 = Thread(target=serverProtocol, args=[STS])
        threads.append(th1)
        th1.start()

        # recursive lookup thread, initially to build the routing table
        result = request.KademliaProtocol(STS).findNode(packet.xxhashUser('netsec41'), ('172.18.0.252', 1337))
        th2 = Thread(target=selfLookup, args=[STS, threads_inner, result])
        threads.append(th2)
        th2.start()

        # wait for the recursive lookup to complete
        th2.join()
        threads.remove(th2)

        # initiate the thread to store data onto the nodes
        th3 = Thread(target=storeOnNodes, args=[STS])
        threads.append(th3)
        th3.start()

        # initiate the thread to update current certificate status
        th4 = Thread(target=updateCertificateStatus, args=[STS])
        threads.append(th4)
        th4.start()

        # wait for all threads to complete
        for t in threads:
            t.join()

    # terminate all connections on interrupt
    except KeyboardInterrupt:
        for nodes in STS.STSConnectionStates.keys():
            addr = sts_utility.addrStringToTuple(nodes)
            STS.terminate(addr)
        sock.close()