#!/usr/bin/env python

# Created for the MITRE STEM CTF
# Author: Stephen DiCato

import sys
import base64
import binascii
import pprint

try:
    from Crypto.Cipher import DES

except ImportError as e:
    print "You need to install pyCrypto!"
    sys.exit(1)

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def create():
    # Use DES in ECB mode with a key of 'H@ck3rs1' to encrypt a flag,
    # pad it to 256 bytes, then split it into 32 bytes to be send over
    # the network (see the echoserv/echoclient files)
    
    # The holy flag!
    flag = 'MCA-8B9B37E3'
    plaintext = '.' * ((256 - len(flag)) / 2) + flag + '.' * ((256 - len(flag)) / 2)
    key = 'H@ck3rs1'

    c = DES.new(key, DES.MODE_ECB)
    ciphertext = c.encrypt(plaintext)

    payloads = [binascii.hexlify(x) for x in chunks(ciphertext, 32)]

    # Print out the encrypted payloads
    pprint.pprint(payloads)

def solve():
    # Do whatever you want to get the TCP payloads out of the session
    # You can manually pull them out of wireshark, or use pynids, scapy,
    # or many many different tools. I bet most will do it manually since it is
    # a pretty short session.

    # Once you pull out the session, students should recognize the first
    # data blob sent from client --> server is base64 encoded

    first_payload = "START::TEVOOjI1NixDSVBIRVI6REVTLE1PREU6RUNCLEtFWTpIQGNrM3JzMQ=="

    # If we take everything after the 'START::'  and base64 decode it, you end up:
    # 'LEN:256,CIPHER:DES,MODE:ECB,KEY:H@ck3rs1'
    
    stuff = base64.b64decode("TEVOOjI1NixDSVBIRVI6REVTLE1PREU6RUNCLEtFWTpIQGNrM3JzMQ==")

    # You can then look at the rest of the payloads sent from client --> server, append
    # then all together, and try to decrypt them using DES in ECB mode with a key of 'H@ck3rs1'

    ciphertext = ['00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
     '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
     '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
     '00034af6c332f5b900034af6c332f5b900034af6c332f5b9552ce4a0c4f85eab',
     '59cdb8c40b8b13d800034af6c332f5b900034af6c332f5b900034af6c332f5b9',
     '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
     '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
     '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9']

    # Join all the payloads together and unhexlify them 
    big_blob = binascii.unhexlify(''.join(ciphertext))
     
    # Then use the DES in ECB mode and decrypt the blob
    key = 'H@ck3rs1'
    c = DES.new(key, DES.MODE_ECB)
    plaintext = c.decrypt(big_blob)

    # And of course, when you print it you see the flag
    print plaintext

if __name__ == '__main__':
    """
    """
    if sys.argv[1] == 'create':
        create()
    elif sys.argv[1] == 'solve':
        solve()
        
