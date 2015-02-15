MITRE STEM CTF
Networking 200 Challenge

The students receive 'challenge.pcap' and have to find a flag.

Files:
	challenge-networking-200.pcap - the file to give to students
	challenge.py - used to create and solve the challenge
	echoserv.py & echoclient.py - server and client used to send the encrypted data across the wire in order to easily capture the packets with tcpdump

The flag was padded to 256 bytes, encrypted with DES in ECB mode with the key 'H@ck3rs1', split into 32 byte chunks and sent from a client to server over localhost on port 8000. The client sends a 'protocol handshake' that is base64 encoded, but contains the length of the data, the cipher/mode/key used. This mimics HTTP basic auth and makes the challenge solvable given the allotted time. 

ONLY DISTRIBUTE THE 'challenge-networking-200.pcap' file to contestants!