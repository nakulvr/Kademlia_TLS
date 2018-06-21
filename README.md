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
