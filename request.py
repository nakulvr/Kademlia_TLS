import struct
import packet

# define Kademlia protocol packets
class KademliaProtocol:

    # set the nodeID, nonce and the STS instance
    def __init__(self, STS):
        self.nodeID = packet.xxhashUser('netsec41')
        self.nonce = packet.nonceGen()
        self.STS = STS

    # send the ping packet and return the nonce of the request
    def ping(self, server_address):
        ping = packet.basic_protocol_request(0)
        print('=== PING SENT ===')
        # self.sock.sendto(ping, server_address)
        self.STS.send(server_address, 1, ping)
        # packet.hex_print(ping)
        return packet.nonceExtract(ping)

    # send the find-node packet and return the nonce of the request
    def findNode(self, nodeID, server_address):
        node = struct.pack('>IH', 2, nodeID)
        find = packet.basic_protocol_request(4) + node
        print('\n=== FIND-NODE ===')
        # self.sock.sendto(find, server_address)
        self.STS.send(server_address, 1, find)
        # packet.hex_print(find)
        return packet.nonceExtract(find)

    # send the find-value packet and return the nonce of the request
    def findValue(self, value, server_address):
        data = struct.pack('>IH', 2, packet.hashData(value))
        findData = packet.basic_protocol_request(6) + data
        print('\n=== FIND-VALUE ===')
        # self.sock.sendto(findData, server_address)
        self.STS.send(server_address, 1, findData)
        # packet.hex_print(findData)
        return packet.nonceExtract(findData)

    # send the store packet and return the nonce of the request
    def store(self, value, server_address):
        data = struct.pack('>I', len(value)) + value
        storeData = packet.basic_protocol_request(2) + data
        print('\n=== STORE-DATA ===', server_address)
        # self.sock.sendto(storeData, server_address)
        self.STS.send(server_address, 1, storeData)
        # packet.hex_print(storeData)
        return packet.nonceExtract(storeData)