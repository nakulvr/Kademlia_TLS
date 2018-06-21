import base64
import struct
import pysodium
from collections import OrderedDict
import time
import binascii
import os

# decoding certificate
def decodeMyCertificate(sock, endpoint_address):

    f = open("/home/netsec41/node.pub", 'r')
    myCert = base64.b64decode(f.readline())
    self_cert = pysodium.crypto_generichash(myCert, outlen=64)
    msg = struct.pack('>I', len(self_cert)) + self_cert
    sock.sendto(msg, endpoint_address)
    data, addr = sock.recvfrom(1500)
    myCertStatus = data
    f.close()
    return (myCert, myCertStatus)

# create a dictionary with the fields of certificate status
def certificateStatusDict(data):
    status_tuple = OrderedDict()
    cp = 0
    status_tuple['S'] = data[cp]
    cp += 1
    length = struct.unpack('>I', data[cp:cp + 4])[0]
    cp += 4
    status_tuple['H'] = data[cp: cp + length]
    cp += length
    byte = 8

    T = struct.unpack('>Q', data[cp: cp + byte])[0]
    status_tuple['T'] = T
    cp += byte

    F = struct.unpack('>Q', data[cp: cp + byte])[0]
    status_tuple['F'] = F
    cp += byte

    U = struct.unpack('>Q', data[cp: cp + byte])[0]
    status_tuple['U'] = U
    cp += byte

    cp += 1
    length = struct.unpack('>I', data[cp:cp + 4])[0]
    cp += 4
    status_tuple['I'] = data[cp: cp + length]
    cp += length

    length = struct.unpack('>I', data[cp:cp + 4])[0]
    cp += 4

    status_tuple['G'] = data[cp: cp + length]
    cp += length
    return status_tuple, cp

# create a dictionary with the fields of certificate
def certificateDict(cert):
    cert_tuple = OrderedDict()
    cp = 1
    length = struct.unpack('>I', cert[cp:cp + 4])[0]
    cp += 4
    cert_tuple['I'] = cert[cp:cp + length]

    cp += length
    length = struct.unpack('>I', cert[cp:cp + 4])[0]

    cp += 4
    cert_tuple['S'] = cert[cp:cp + length]
    cp += length

    cert_tuple['C'] = cert[cp:cp + 4]
    cp += 4

    length = struct.unpack('>I', cert[cp:cp + 4])[0]
    cp += 4
    cert_tuple['K_E'] = cert[cp:cp + length]
    cp += length
    length = struct.unpack('>I', cert[cp:cp + 4])[0]
    cp += 4

    cert_tuple['K_S'] = cert[cp:cp + length]
    cp += length
    length = struct.unpack('>I', cert[cp:cp + 4])[0]
    cp += 4

    cert_tuple['G'] = cert[cp:cp + length]
    cp += length
    return cert_tuple, cp

# unpack the propose packet
def deconstructPropose(data):
    propose_tuple = OrderedDict()
    cp = 0
    propose_tuple['phase'] = data[cp]
    cp += 1
    propose_tuple['P'] = data[cp]
    cp += 1
    length = struct.unpack('>I', data[cp: cp + 4])[0]
    cp += 4
    K_servPK = data[cp: cp + length]
    propose_tuple['K'] = K_servPK
    cp += length
    C, length = certificateDict(data[cp:])
    propose_tuple['C_B'] = data[cp: cp + length]
    propose_tuple['C'] = C
    cp += length
    S, length = certificateStatusDict(data[cp:])
    propose_tuple['S_B'] = data[cp: cp + length]
    propose_tuple['S'] = S
    cp += length
    length = struct.unpack('>I', data[cp: cp + 4])[0]
    cp += 4
    propose_tuple['G'] = data[cp: cp + length]
    return propose_tuple

# unpack the secret key
def decodeSecretKey():
    f = open('/home/netsec41/node.sec', "r")
    mySK = base64.b64decode(f.readline())
    # print(binascii.hexlify(mySK))
    cp = 0
    length = struct.unpack('>I', mySK[cp : cp + 4])[0]
    cp += 4
    K_E = mySK[cp: cp + length]
    cp += length
    length = struct.unpack('>I', mySK[cp: cp + 4])[0]
    cp += 4
    K_S = mySK[cp: cp + length]
    f.close()
    return (K_E, K_S)

# view the STS packet details
def decodeSTSMessage(data):
    try:
        inpt = binascii.hexlify(data).decode('utf-8')
        # packet.hex_print(inpt)
        # print(inpt)
        a = bytearray()
        for i in range(0, len(inpt), 2):
            a.append(int(inpt[i] + inpt[i + 1], 16))

        with open("output.txt", "wb") as f:
            f.write(a)

        os.system('cat output.txt | /usr/bin/dhtutil decode_sts_message')
        os.remove('output.txt')
    except:
        return None

# view the Node packet details
def decodeDHTMessage(data):
    try:
        inpt = binascii.hexlify(data).decode('utf-8')
        # packet.hex_print(inpt)
        # print(inpt)
        a = bytearray()
        for i in range(0, len(inpt), 2):
            a.append(int(inpt[i] + inpt[i + 1], 16))

        with open("output.txt", "wb") as f:
            f.write(a)

        os.system('cat output.txt | /usr/bin/dhtutil decode_dht_message')
        os.remove('output.txt')
    except:
        return None

# view the certificate details
def decodeCertMessage(data):
    try:
        a = base64.b64encode(data)
        with open("output.txt", "wb") as f:
            f.write(a)

        cmd = '/usr/bin/dhtutil decode_cert --cert {0}'.format('output.txt')
        os.system(cmd)
        os.remove('output.txt')
    except:
        return None

# unpack CA certificates
def decodeCACertificates():
    ca_tuple = OrderedDict()
    f1 = open('/home/netsec41/ca_certs.pub', "r")
    for line in f1:
        cert_tuple, lt = certificateDict(base64.b64decode(line))
        ca_tuple[cert_tuple['I']] = cert_tuple
    f1.close()
    return ca_tuple

# convert IP addr to string
def addrToString(addr):
    return addr[0] +':' + str(addr[1])

# create a tuple based on IP:port combination
def addrStringToTuple(str):
    return (str.split(':')[0], int(str.split(':')[1]))

# generate time in a packet format
def timestampPacked():
    return struct.pack('>Q', int(time.time()))