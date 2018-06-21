import binascii
import xxhash
import struct
import os
import message

# print the hex format of the packet
def hex_print(data):
    for i in range(len(data)):
        print(hex(data[i]), end=" ")
    print('')
    print(binascii.hexlify(data))

# Build the IPV4 string
def constructIP(ip_data):
    return str(ip_data[0]) + '.' + str(ip_data[1]) + '.' + str(ip_data[2]) + '.' + str(ip_data[3])

# return the IPV4 as a byte address
def deconstructIP(ip_data):
    ip = ip_data.split('.')
    packedIP = b''
    for data in ip:
        packedIP += struct.pack('>B', int(data))
    return packedIP

# enconde the userID
def xxhashUser(data):
    return xxhash.xxh64(data).intdigest() & 0xffff

# encode the data
def hashData(data):
    return xxhash.xxh64(data).intdigest() & 0xffff

# generate the nonce
def nonceGen():
    return int.from_bytes(os.urandom(2), byteorder='big') & 0xffff

# create the basic request packet
def basic_protocol_request(firstByte):
    nonce = nonceGen()
    message.Messages().insertRequest(nonce)
    return struct.pack('>BIHIH', firstByte, 2, xxhashUser('netsec41'), 2, nonce)

# extract nonce from the packet
def nonceExtract(data):
    return struct.unpack('>H', data[11:13])[0]

# return the basic response packet
def basic_protocol_response(firstByte, data):
    return struct.pack('>BIHIH', firstByte, 2, xxhashUser('netsec41'), 2, nonceExtract(data))

# return a ping response packet
def pingResponse(data):
    return basic_protocol_response(1, data)

# return a store response packet
def storeResponse(data):
    return basic_protocol_response(3, data)

# return IPV4 response packet
def IPv4Response(data):
    return struct.pack('>B', 4) + data[0] + struct.pack('>HIH', data[1], 2, data[2])

# return IPV6 response packet
def IPv6Response(data):
    return struct.pack('>B', 6) + data[0] + struct.pack('>HIH', data[1], 2, data[2])

# return find-node response
def findNodeResponse(data, lookup):
    finalPack = b''
    for i in lookup:
        if len(i[0]) == 4:
            finalPack = finalPack + IPv4Response(i)
        if len(i[0]) == 16:
            finalPack = finalPack + IPv6Response(i)

    return basic_protocol_response(5, data) + struct.pack('>I', len(finalPack)) + finalPack

# return find-value response (data part)
def findValueResponseData(data, value):
    return basic_protocol_response(7, data) + struct.pack('>I', 0) + struct.pack('>I', len(value)) + value

# return find-value response (node details part based on IPV4/IPV6)
def findValueResponseNode(data, lookup):
    finalPack = b''
    for i in lookup:
        if len(i[0]) == 4:
            finalPack = finalPack + IPv4Response(i)
        if len(i[0]) == 16:
            finalPack = finalPack + IPv6Response(i)
    return basic_protocol_response(7, data) + struct.pack('>I', len(finalPack)) + finalPack + struct.pack('>I', 0)

# return the length of the packet as an int
def unpackReceivedInt(data):
    length = struct.unpack('>I', data[13:17])[0]
    return struct.unpack('>H', data[17: length + 17])[0]

# return the data part of the packet
def unpackReceivedData(data):
    length = struct.unpack('>I', data[13:17])[0]
    # return struct.unpack('>H', data[17: length + 17])[0]
    return data[17: length + 17]

# return the nodeID from the packet
def unpackNodeID(data):
    length = struct.unpack('>I', data[1:5])[0]
    return struct.unpack('>H', data[5: length + 5])[0]

# return an error packet
def errorResponse(data):
    errorMessage = 'WRONG PACKET FORMAT'.encode('utf-8')
    return basic_protocol_response(8, data) + struct.pack('>I', len(errorMessage)) + errorMessage

# TEST DATA
# routing_data = {'0000001000000000': [b'\xac\x12\x00\xfc', 2001, 512, '0000001000000000'],
#  '0011110000000000': [b'\xac\x12\x00\xfc', 2030, 15360, '0011110000000000'],
#  '0100000000000000': [b'\xac\x12\x00\xfc', 2032, 16384, '0100000000000000'],
#  '0100001000000000': [b'\xac\x12\x00\xfc', 2033, 16896, '0100001000000000'],
#  '0100011000000000': [b'\xac\x12\x00\xfc', 2035, 17920, '0100011000000000'],
#  '0100110000000000': [b'\xac\x12\x00\xfc', 2038, 19456, '0100110000000000'],
#  '0100111000000000': [b'\xac\x12\x00\xfc', 2039, 19968, '0100111000000000'],
#  '0101000000000000': [b'\xac\x12\x00\xfc', 2040, 20480, '0101000000000000'],
#  '0101001000000000': [b'\xac\x12\x00\xfc', 2041, 20992, '0101001000000000'],
#  '0101010000000000': [b'\xac\x12\x00\xfc', 2042, 21504, '0101010000000000'],
#  '0101011000000000': [b'\xac\x12\x00\xfc', 2043, 22016, '0101011000000000'],
#  '0101100000000000': [b'\xac\x12\x00\xfc', 2044, 22528, '0101100000000000'],
#  '0101101000000000': [b'\xac\x12\x00\xfc', 2045, 23040, '0101101000000000'],
#  '0101110000000000': [b'\xac\x12\x00\xfc', 2046, 23552, '0101110000000000'],
#  '0101111000000000': [b'\xac\x12\x00\xfc', 2047, 24064, '0101111000000000'],
#  '0110011000000000': [b'\xac\x12\x00\xfc', 2051, 26112, '0110011000000000'],
#  '0110100000000000': [b'\xac\x12\x00\xfc', 2052, 26624, '0110100000000000'],
#  '0110101000000000': [b'\xac\x12\x00\xfc', 2053, 27136, '0110101000000000'],
#  '0111000000000000': [b'\xac\x12\x00\xfc', 2056, 28672, '0111000000000000'],
#  '0111110000000000': [b'\xac\x12\x00\xfc', 2062, 31744, '0111110000000000']}