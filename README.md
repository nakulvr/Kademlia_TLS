# Kademlia_TLS
### A Distributed Hash Table using Kademlia for peer-to-peer communication (with simple TLS)

Kademlia is a simple yet widely-used **distributed hash table (DHT)** that forms the basis for a number of peer-to-peer network applications. Kademlia uses an XOR-based distance metric for points in a key space that contains both DHT nodes and key-value pairs. This distance metric is used to build routing tables that are essentially binary trees, though tables are instead organized using a construction termed a k-bucket that is well-suited to Kademlia’s lookup algorithm.

The following presents a succinct description of a Kademlia protocol variant that will be the basis for our network. 

Parameter | Original Version | Our Version
--- | --- | --- 
k | 20 nodes | 40 nodes
Hash Function | SHA-1 | xxh64(data) & 0xffff
Node ID |	Random | xxh64(user) & 0xffff
Key space	| 160 bits |	16 bits
Nonce length |	160 bits	| 16 bits
Cache time	| 24 hours	| 5 minutes

For our DHT, we will implement a (very) simplified variant to provide our desired security properties of message confidentiality, message integrity, and node authentication. We will call this protocol Simple Transport Security, or STS

Protocol
In the spirit of TLS, STS is constructed as an application-agnostic security layer that encapsulates a higher-level application protocol. That is, STS messages are composed of a header followed by an opaque application-level data payload. All messages share the following properties:

1. Integer fields are encoded in big-endian format
2. All length fields are denoted in bytes
3. Message types are indicated by the first byte
4. Timestamps are denoted in seconds since UNIX epoch

STS establishes a concept of an STS session, independent of any similar notion at other networking layers. The protocol proceeds in three distinct phases: session negotiation, data exchange, and session termination.

Allowed cipher suites include those in the following table. STS implementations are required to support all table entries, but may refuse certain values.

Value |	Authentication and Key Exchange	| Session Cipher
--- | --- | --- 
0	| x25519blake2b	| null
1	| x25519blake2b	| chacha20_poly1305_ietf
2 |	x25519blake2b |	chacha20_poly1305
3 |	x25519xsalsa20poly1305 |	null
4	| x25519xsalsa20poly1305 | chacha20_poly1305_ietf
5	| x25519xsalsa20poly1305 | chacha20_poly1305
