import time
import socket
import pysodium
import struct
import packet
from collections import OrderedDict
import sts_utility
import time
import pprint
# Simple Transport Security (Simpler version of a TLS)

class STS:
    # Maintain the connection states of all nodes
    STSConnectionStates = OrderedDict()
    CAcerts = sts_utility.decodeCACertificates()

    def __init__(self, sock, myCert, myCertStatus):
        self.sock = sock
        self.endpoint_address = ('172.18.0.252', 3333)
        self.myCert = myCert
        self.myCertStatus = myCertStatus
        self.myEncrypKey, self.mySignKey = sts_utility.decodeSecretKey()

    def cleanConnectionStates(self):
        print('=== CLEANING CONNECTIONS ===')
        # pprint.pprint(STS.STSConnectionStates)
        for nodes in STS.STSConnectionStates.keys():
            if STS.STSConnectionStates[nodes]['phase'] != 2:
                currTime = int(time.time())
                if currTime - STS.STSConnectionStates[nodes]['time'] > 300:
                    addr = sts_utility.addrStringToTuple(nodes)
                    print('=== REMOVE CONNECTIONS ===', addr)
                    self.terminate(addr)

    def setCertificateStatus(self, myCertstatus):
        self.myCertStatus = myCertstatus

    def getCertificateStatus(self):
        return self.myCertStatus

    # Validate the subject principal
    def subjectPrincipalCheck(self, addr, certTuple):
        subject = certTuple['S']
        try:
            if subject[0] == 0:
                cp = 1
                length = struct.unpack('>I', subject[cp: cp + 4])[0]
                cp += 4
                cp += length
                ip_data = subject[cp:]
                if ip_data[0] == 4:
                    ip = packet.constructIP(ip_data[1:5])
                    port = struct.unpack('>H', ip_data[5:7])[0]
                    if ip != addr[0]:
                        print('Wrong node IP')
                        return False
                    if port != addr[1]:
                        print('Wrong node PORT')
                        return False
                # TODO IPV6 check
                else:
                    return False
            elif subject[0] == 4:
                ip_data = subject
                ip = packet.constructIP(ip_data[1:5])
                port = struct.unpack('>H', ip_data[5:7])[0]
                if ip != addr[0]:
                    print('Wrong node IP')
                    return False
                if port != addr[1]:
                    print('Wrong node PORT')
                    return False
            else:
                print('Wrong Principal format / IPv6')
                return False
        except:
            print('Exception while verifying the subject principal')
            return False
        return True

    # verify the propose message, checks based on:
    # 1. Certificate
    # 2. Certificate status
    # 3. Message signature check
    # 4. Capability
    def verifyPropose(self, data, addr):
        propose_tuple = sts_utility.deconstructPropose(data)

        # 1. Certificate Checks
        if propose_tuple['C']['I'] not in STS.CAcerts.keys():
            print('wrong issuer principal')
            return False
        for I, _ in STS.CAcerts.items():
            if propose_tuple['C']['I'] == I:
                ca_cert_tuple = STS.CAcerts[I]
        try:
            pysodium.crypto_sign_verify_detached(propose_tuple['C']['G'],
                                                 propose_tuple['C_B'][: -64] + (0).to_bytes(64, byteorder='big'),
                                                 ca_cert_tuple['K_S'])
        except:
            print('wrong certificate signature')
            return False

        # CA DEPTH
        if ca_cert_tuple['C'][0] == 0:
            print('wrong CA depth')
            return False

        if not self.subjectPrincipalCheck(addr, propose_tuple['C']):
            print('wrong subject principal')
            return False

        # 4. NODE CAPABILITIES
        if not (propose_tuple['C']['C'][1:4] == b'\x00\x00\x1f' or propose_tuple['C']['C'][1:4] == b'\x00\x00?'):
            print('wrong capabilities')
            return False

        # 2. Certificate Status check
        try:
            pysodium.crypto_sign_verify_detached(propose_tuple['S']['G'],
                                                 propose_tuple['S_B'][: -64] + (0).to_bytes(64, byteorder='big'),
                                                 ca_cert_tuple['K_S'])
        except:
            print('wrong status signature')
            return False

        if pysodium.crypto_generichash(propose_tuple['C_B'], outlen=64) != propose_tuple['S']['H']:
            print('wrong status HASH')
            return False

        if propose_tuple['S']['S'] != 1:
            print('wrong cert status validity')
            return False

        currTime = int(time.time())
        if propose_tuple['S']['F'] + propose_tuple['S']['U'] <= currTime:
            print('wrong cert status, validity expired')
            return False

        #  3. Message signature:
        try:
            pysodium.crypto_sign_verify_detached(propose_tuple['G'],
                                                 data[: -64] + (0).to_bytes(64, byteorder='big'),
                                                 propose_tuple['C']['K_S'])
        except:
            print('wrong propose message signature')
            return False

        return True

    # [key exchange to establish session]
    # generate a propose message using Elliptic curve Diffie–Hellman (ECDH)keys
    def generateProposeECDH(self, cSuite, pubkey, signkey, senderCertificate, statusCertificate):
        G_temp = struct.pack('>BBI', 0, cSuite, len(pubkey)) + pubkey + senderCertificate + statusCertificate
        zeroSig = (0).to_bytes(64, byteorder='big')
        G = G_temp + struct.pack('>I', len(zeroSig)) + zeroSig
        G = pysodium.crypto_sign_detached(G, signkey)
        # print(len(G_temp + struct.pack('>I', len(G)) + G))
        return G_temp + struct.pack('>I', len(G)) + G

    # [key exchange to agree on a session key and then establish session]
    # generate a propose message using Public-key authenticated encryption (salsa-poly)
    def genProposeSalsa(self, cSuite, servPubkey, sessionKey, myEncrypKey, mySignKey, senderCertificate,
                        statusCertificate):
        nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        encrypSession = pysodium.crypto_box(sessionKey, nonce, servPubkey, myEncrypKey)
        # encrypSession = pysodium.randombytes(32)
        G_temp = struct.pack('>BBI', 0, cSuite,
                             len(nonce + encrypSession)) + nonce + encrypSession + senderCertificate + statusCertificate
        zeroSig = (0).to_bytes(64, byteorder='big')
        G = G_temp + struct.pack('>I', len(zeroSig)) + zeroSig
        G = pysodium.crypto_sign_detached(G, mySignKey)
        return G_temp + struct.pack('>I', len(G)) + G

    # decrypt a salsa-poly encryption
    def decryptSalsaSession(self, proposeTuple, myEncrypKey):
        cp = 0
        nonce = proposeTuple['K'][cp:cp + 24]
        cp += 24
        cipherText = proposeTuple['K'][cp:]
        # encrypSession = pysodium.crypto_box(cipherText, nonce, servPubkey, myEncrypKey)
        try:
            salsaSession = pysodium.crypto_box_open(cipherText, nonce, proposeTuple['C']['K_E'], myEncrypKey)
        except:
            salsaSession = None
        return salsaSession

    # create a STS response packet
    # encryption based on either crypto_aead_chacha20poly1305 or crypto_aead_chacha20poly1305_itef
    def constructSTSResponse(self, mType, addr, exchangeData):
        data = None
        addrStr = sts_utility.addrToString(addr)
        if addrStr in STS.STSConnectionStates.keys():

            if STS.STSConnectionStates[addrStr]['cSuite'] == 1 or STS.STSConnectionStates[addrStr]['cSuite'] == 4:
                nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_ietf_NONCEBYTES)
                m = struct.pack('>B', mType) + struct.pack('>I', len(nonce))
                encrypData = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(exchangeData, m, nonce,
                                                                                STS.STSConnectionStates[addrStr][
                                                                                    'session_key'][:32])
                data = m + nonce + encrypData

            elif STS.STSConnectionStates[addrStr]['cSuite'] == 2 or STS.STSConnectionStates[addrStr]['cSuite'] == 5:
                nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NONCEBYTES)
                m = struct.pack('>B', mType) + struct.pack('>I', len(nonce))
                encrypData = pysodium.crypto_aead_chacha20poly1305_encrypt(exchangeData, m, nonce,
                                                                           STS.STSConnectionStates[addrStr][
                                                                               'session_key'][:32])
                data = m + nonce + encrypData
        return data

    # unpack and decrypt based on encryption based on either crypto_aead_chacha20poly1305 or crypto_aead_chacha20poly1305_itef
    def deconstructSTSResponse(self, data, addr):
        # m = None
        decrypData = None
        addrStr = sts_utility.addrToString(addr)
        if addrStr in STS.STSConnectionStates.keys():
            cp = 0
            m = struct.pack('>B', data[cp])
            # if data[cp] == 2:
            cp += 1
            nonce_length = data[cp: cp + 4]
            length = struct.unpack('>I', nonce_length)[0]
            m += nonce_length
            cp += 4
            nonce = data[cp: cp + length]
            cp += length
            encrypData = data[cp:]
            if STS.STSConnectionStates[addrStr]['cSuite'] == 1 or STS.STSConnectionStates[addrStr]['cSuite'] == 4:
                try:
                    decrypData = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt(encrypData, m, nonce,
                                                                                    STS.STSConnectionStates[addrStr][
                                                                                        'session_key'][:32])
                except:
                    decrypData = None

            # TODO suites 2 or 5
            elif STS.STSConnectionStates[addrStr]['cSuite'] == 2 or STS.STSConnectionStates[addrStr]['cSuite'] == 5:
                try:
                    decrypData = pysodium.crypto_aead_chacha20poly1305_decrypt(encrypData, m, nonce,
                                                                               STS.STSConnectionStates[addrStr][
                                                                                   'session_key'][:32])
                except:
                    decrypData = None

        return decrypData

    # blake2b hash generation
    def blake2b(self, data, addr, server=False):
        # ECDH_AED_accept = None
        addrStr = sts_utility.addrToString(addr)
        proposeResp = sts_utility.deconstructPropose(data)
        # print(STS.STSConnectionStates)
        # if addrStr in STS.STSConnectionStates.keys():
        myECDHPK, myECDHSK = STS.STSConnectionStates[addrStr]['keys']
        # TODO verification
        scalarmult_q = pysodium.crypto_scalarmult_curve25519(myECDHSK, proposeResp['K'])
        genericHash = pysodium.crypto_generichash_init(outlen=64)
        genericHash = pysodium.crypto_generichash_update(genericHash, scalarmult_q)
        if not server:
            genericHash = pysodium.crypto_generichash_update(genericHash, myECDHPK)
            genericHash = pysodium.crypto_generichash_update(genericHash, proposeResp['K'])
        else:
            genericHash = pysodium.crypto_generichash_update(genericHash, proposeResp['K'])
            genericHash = pysodium.crypto_generichash_update(genericHash, myECDHPK)

        genericHash = pysodium.crypto_generichash_final(genericHash, outlen=64)

        STS.STSConnectionStates[addrStr]['session_key'] = genericHash
        STS.STSConnectionStates[addrStr]['time'] = int(time.time())

    # send a Blake2b response packet
    def sendBlake2bResp(self, data, addr, cSuite):
        addrStr = sts_utility.addrToString(addr)
        # myCert, myCertStatus = sts_utility.decodeMyCertificate(self.sock, self.endpoint_address)
        # myEncrypKey, mySignKey = sts_utility.decodeSecretKey()
        if cSuite in [1, 2]:
            # print('sending ECDH')
            myECDHPK, myECDHSK = pysodium.crypto_kx_keypair()
            propose = self.generateProposeECDH(cSuite, myECDHPK, self.mySignKey, self.myCert, self.myCertStatus)
            # STS.STSConnectionStates[addrStr] = {'session_key': None, 'phase': 0, 'init': True,
            #                                     'keys': (myECDHPK, myECDHSK),
            #                                     'cSuite': cSuite, 'time': int(time.time())}
            STS.STSConnectionStates[addrStr]['keys'] = (myECDHPK, myECDHSK)
            self.blake2b(data, addr, server=True)
            self.sock.sendto(propose, addr)
        elif cSuite == 0:
            myECDHPK, myECDHSK = pysodium.crypto_kx_keypair()
            STS.STSConnectionStates[addrStr]['keys'] = (myECDHPK, myECDHSK)
            propose = self.generateProposeECDH(1, myECDHPK, self.mySignKey, self.myCert, self.myCertStatus)
            self.sock.sendto(propose, addr)

    # salsapoly response message
    def salsa20poly1305(self, data, addr, server=False):
        salsaMsg = None
        addrStr = sts_utility.addrToString(addr)

        if not server:
            if STS.STSConnectionStates[addrStr]['cSuite'] == 3:
                mySalsaSession = pysodium.randombytes(32)
                proposeResp = sts_utility.deconstructPropose(data)
                salsaMsg = self.genProposeSalsa(proposeResp['P'], proposeResp['C']['K_E'], mySalsaSession,
                                                self.myEncrypKey, self.mySignKey,
                                                self.myCert, self.myCertStatus)
                STS.STSConnectionStates[addrStr]['session_key'] = mySalsaSession
                STS.STSConnectionStates[addrStr]['cSuite'] = proposeResp['P']
                STS.STSConnectionStates[addrStr]['time'] = int(time.time())

            elif STS.STSConnectionStates[addrStr]['cSuite'] in [4, 5]:
                STS.STSConnectionStates[addrStr]['phase'] = 1
                salsaMsg = self.constructSTSResponse(1, addr, sts_utility.timestampPacked())
        else:
            proposeReq = sts_utility.deconstructPropose(data)
            if STS.STSConnectionStates[addrStr]['cSuite'] == 3 and STS.STSConnectionStates[addrStr]['phase'] == 0:

                salsaMsg = self.genProposeSalsa(4, proposeReq['C']['K_E'], (0).to_bytes(32, byteorder='big'),
                                                self.myEncrypKey, self.mySignKey,
                                                self.myCert, self.myCertStatus)
                STS.STSConnectionStates[addrStr]['session_key'] = (0).to_bytes(32, byteorder='big')
                STS.STSConnectionStates[addrStr]['cSuite'] = 4
                STS.STSConnectionStates[addrStr]['time'] = int(time.time())
            elif STS.STSConnectionStates[addrStr]['cSuite'] in [4, 5] and STS.STSConnectionStates[addrStr][
                'phase'] == 0:
                session_key = self.decryptSalsaSession(proposeReq, self.myEncrypKey)
                if not session_key:
                    salsaMsg = self.genProposeSalsa(STS.STSConnectionStates[addrStr]['cSuite'],
                                                    proposeReq['C']['K_E'], (0).to_bytes(32, byteorder='big'),
                                                    self.myEncrypKey, self.mySignKey,
                                                    self.myCert, self.myCertStatus)
                    STS.STSConnectionStates[addrStr]['session_key'] = (0).to_bytes(32, byteorder='big')
                    STS.STSConnectionStates[addrStr]['cSuite'] = STS.STSConnectionStates[addrStr]['cSuite']
                    STS.STSConnectionStates[addrStr]['time'] = int(time.time())
                else:
                    STS.STSConnectionStates[addrStr]['session_key'] = session_key
                    salsaMsg = self.genProposeSalsa(4, proposeReq['C']['K_E'], (0).to_bytes(32, byteorder='big'),
                                                    self.myEncrypKey, self.mySignKey,
                                                    self.myCert, self.myCertStatus)
                    STS.STSConnectionStates[addrStr]['cSuite'] = proposeReq['P']
                    STS.STSConnectionStates[addrStr]['time'] = int(time.time())

        return salsaMsg

    # terminate message response
    def terminate(self, addr):
        print('=== SEND TERMINATE ===', addr)
        addrStr = sts_utility.addrToString(addr)
        if addrStr not in STS.STSConnectionStates.keys():
            terminate = struct.pack('>BI', 3, len((0).to_bytes(8, byteorder='big'))) + (0).to_bytes(8, byteorder='big')
            self.sock.sendto(terminate, addr)
        elif STS.STSConnectionStates[addrStr]['session_key'] is not None:
            terminate = self.constructSTSResponse(3, addr, sts_utility.timestampPacked())
            self.sock.sendto(terminate, addr)
            STS.STSConnectionStates.pop(addrStr)
        else:
            terminate = struct.pack('>BI', 3, len((0).to_bytes(8, byteorder='big'))) + (0).to_bytes(8, byteorder='big')
            self.sock.sendto(terminate, addr)
            STS.STSConnectionStates.pop(addrStr)

    # negotiation phase (exchanges until a session key is agreed upon after verifications)
    def negotiate(self, data, addr):
        addrStr = sts_utility.addrToString(addr)
        if addrStr in STS.STSConnectionStates.keys():
            # SERVER LOGIC
            if not STS.STSConnectionStates[addrStr]['init']:
                if STS.STSConnectionStates[addrStr]['cSuite'] in [0, 1, 2] and STS.STSConnectionStates[addrStr][
                    'phase'] == 0:
                    self.sendBlake2bResp(data, addr, STS.STSConnectionStates[addrStr]['cSuite'])
                elif STS.STSConnectionStates[addrStr]['cSuite'] in [1, 2] and STS.STSConnectionStates[addrStr][
                    'phase'] == 1:
                    # TODO verify accept
                    # ACCEPT Verify
                    ECDH_AED_accept = self.constructSTSResponse(1, addr, sts_utility.timestampPacked())
                    sts_utility.decodeSTSMessage(ECDH_AED_accept)
                    STS.STSConnectionStates[addrStr]['phase'] = 2
                    self.sock.sendto(ECDH_AED_accept, addr)
                    # self.receive()

                elif STS.STSConnectionStates[addrStr]['cSuite'] in [3, 4, 5] and STS.STSConnectionStates[addrStr][
                    'phase'] == 0:
                    salsaMsg = self.salsa20poly1305(data, addr, server=True)
                    if not salsaMsg:
                        self.terminate(addr)
                    else:
                        sts_utility.decodeSTSMessage(salsaMsg)
                        self.sock.sendto(salsaMsg, addr)

                elif STS.STSConnectionStates[addrStr]['cSuite'] in [4, 5] and STS.STSConnectionStates[addrStr][
                    'phase'] == 1:
                    STS.STSConnectionStates[addrStr]['phase'] = 2
                    SALSA_AED_accept = self.constructSTSResponse(1, addr, sts_utility.timestampPacked())
                    sts_utility.decodeSTSMessage(SALSA_AED_accept)
                    self.sock.sendto(SALSA_AED_accept, addr)

                else:
                    self.terminate(addr)

            # CLIENT LOGIC
            else:
                if STS.STSConnectionStates[addrStr]['cSuite'] in [1, 2] and STS.STSConnectionStates[addrStr][
                    'phase'] == 0:
                    if STS.STSConnectionStates[addrStr]['session_key'] is None:
                        self.blake2b(data, addr)
                        ECDH_AED_accept = self.constructSTSResponse(1, addr, sts_utility.timestampPacked())
                        sts_utility.decodeSTSMessage(ECDH_AED_accept)
                        STS.STSConnectionStates[addrStr]['phase'] = 1
                        self.sock.sendto(ECDH_AED_accept, addr)

                elif STS.STSConnectionStates[addrStr]['cSuite'] in [3, 4, 5]:

                    salsaMsg = self.salsa20poly1305(data, addr)
                    sts_utility.decodeSTSMessage(salsaMsg)

                    self.sock.sendto(salsaMsg, addr)

                else:
                    self.terminate(addr)

    # send data to node over STS(establish session if no session exists)
    def send(self, addr, cSuite, nodeData):
        try:
            addrStr = sts_utility.addrToString(addr)
            if addrStr in STS.STSConnectionStates.keys():
                if STS.STSConnectionStates[addrStr]['phase'] == 2:
                    print('send data with the existing session')
                    ECDH_DATA_EX = self.constructSTSResponse(2, addr, nodeData)
                    self.sock.sendto(ECDH_DATA_EX, addr)
                    # self.receive()
                else:
                    self.terminate(addr)

            else:
                print('send data with the new session')

                if cSuite in [1, 2]:

                    myECDHPK, myECDHSK = pysodium.crypto_kx_keypair()
                    propose = self.generateProposeECDH(cSuite, myECDHPK, self.mySignKey, self.myCert, self.myCertStatus)
                    STS.STSConnectionStates[addrStr] = {'session_key': None, 'phase': 0, 'init': True, 'data': nodeData,
                                                        'keys': (myECDHPK, myECDHSK),
                                                        'cSuite': cSuite, 'time': int(time.time())}
                    self.sock.sendto(propose, addr)
                elif cSuite in [3, 4, 5]:
                    propose = self.generateProposeECDH(3, (0).to_bytes(32, byteorder='big'), self.mySignKey, self.myCert,
                                                       self.myCertStatus)
                    STS.STSConnectionStates[addrStr] = {'session_key': None, 'phase': 0, 'init': True, 'data': nodeData,
                                                        'keys': None,
                                                        'cSuite': cSuite, 'time': int(time.time())}
                    self.sock.sendto(propose, addr)

        except:
            return None

            # TODO phase downgrade checks

    def receive(self):

        data, addr = self.sock.recvfrom(1500)
        addrStr = sts_utility.addrToString(addr)
        # Received propose
        # Reply propose for actual suite when 0/3 used
        try:
            if addr == self.endpoint_address:
                self.setCertificateStatus(data)

            elif data[0] == 0:
                # propose received as server
                # print(self.verifySTSResponse(data, addr))
                # CLIENT PROPOSE / MULTIPLE PROPOSE
                if addrStr in STS.STSConnectionStates.keys():
                    if self.verifyPropose(data, addr):
                        if STS.STSConnectionStates[addrStr]['phase'] != 0:
                            self.terminate(addr)
                        elif data[1] < STS.STSConnectionStates[addrStr]['cSuite']:
                            self.terminate(addr)
                        elif STS.STSConnectionStates[addrStr]['phase'] == 0:

                            if STS.STSConnectionStates[addrStr]['init']:
                                if STS.STSConnectionStates[addrStr]['cSuite'] in [1, 2]:
                                    # LOWER SUITE CHECKED BEFORE
                                    if STS.STSConnectionStates[addrStr]['cSuite'] != data[1]:
                                        data = STS.STSConnectionStates[addrStr]['data']
                                        STS.STSConnectionStates.pop(addrStr)
                                        self.send(addr, data[1], data)
                                        return None, None

                                elif STS.STSConnectionStates[addrStr]['cSuite'] == 3 and data[1] == 3:
                                    self.terminate(addr)
                            else:
                                if STS.STSConnectionStates[addrStr]['cSuite'] in [1, 2] and data[1] in [3, 4, 5]:
                                    self.terminate(addr)

                        else:
                            STS.STSConnectionStates[addrStr]['cSuite'] = data[1]
                            STS.STSConnectionStates[addrStr]['time'] = int(time.time())
                    else:
                        print('=== VERIFICATION FAILED ===', addr)
                        self.terminate(addr)

                # SERVER RECEIVE
                else:
                    if self.verifyPropose(data, addr):
                        # if data[1] == 0:
                        # TODO PROPOSE EXPECTED SUITE

                        if addrStr not in STS.STSConnectionStates.keys():
                            STS.STSConnectionStates[addrStr] = {'session_key': None, 'phase': data[0], 'init': False,
                                                                'keys': None,
                                                                'cSuite': data[1], 'time': int(time.time())}
                    else:
                        print('=== VERIFICATION FAILED ===', addr)
                        self.terminate(addr)
                self.negotiate(data, addr)

            elif data[0] == 1:
                if addrStr not in STS.STSConnectionStates.keys():
                    self.terminate(addr)
                elif not self.deconstructSTSResponse(data, addr):
                    self.terminate(addr)
                else:
                    if STS.STSConnectionStates[addrStr]['init']:
                        if STS.STSConnectionStates[addrStr]['phase'] == 1:
                            STS.STSConnectionStates[addrStr]['phase'] = 2
                            ECDH_DATA_EX = self.constructSTSResponse(2, addr, STS.STSConnectionStates[addrStr]['data'])
                            self.sock.sendto(ECDH_DATA_EX, addr)
                        else:
                            self.terminate(addr)

                    else:
                        if STS.STSConnectionStates[addrStr]['phase'] == 0 and STS.STSConnectionStates[addrStr][
                            'cSuite'] in [1, 2]:
                            STS.STSConnectionStates[addrStr]['phase'] = 1
                            self.negotiate(data, addr)
                        elif STS.STSConnectionStates[addrStr]['phase'] == 0 and STS.STSConnectionStates[addrStr][
                            'cSuite'] in [4, 5]:
                            STS.STSConnectionStates[addrStr]['phase'] = 1
                            self.negotiate(data, addr)
                        else:
                            self.terminate(addr)

            elif data[0] == 2:

                if addrStr not in STS.STSConnectionStates.keys():
                    self.terminate(addr)
                elif not self.deconstructSTSResponse(data, addr):
                    self.terminate(addr)
                else:
                    if addrStr in STS.STSConnectionStates.keys():
                        if STS.STSConnectionStates[addrStr]['init']:
                            if STS.STSConnectionStates[addrStr]['phase'] == 2:
                                data_ex_resp = self.deconstructSTSResponse(data, addr)
                                sts_utility.decodeDHTMessage(data_ex_resp)
                                return data_ex_resp, addr
                            else:
                                self.terminate(addr)
                        else:
                            if STS.STSConnectionStates[addrStr]['phase'] == 2:
                                data_ex_resp = self.deconstructSTSResponse(data, addr)
                                return data_ex_resp, addr

                    else:
                        self.terminate(addr)

            elif data[0] == 3:
                print('=== TERMINATE RECEIVED ===', addr)
                sts_utility.decodeSTSMessage(data)
                if addrStr in STS.STSConnectionStates.keys():
                    STS.STSConnectionStates.pop(addrStr)
        except:
            self.terminate(addr)
            return None, None

        return None, None