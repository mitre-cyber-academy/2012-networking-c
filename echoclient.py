#!/usr/bin/env python

# Created for the MITRE STEM CTF
# Author: Stephen DiCato

import sys
import base64
import binascii
from twisted.internet.protocol import ClientFactory, Protocol
from twisted.internet import reactor

# If you run 'python pcap_challenge.py create' you get these payloads
ciphertext = ['00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
 '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
 '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
 '00034af6c332f5b900034af6c332f5b900034af6c332f5b9552ce4a0c4f85eab',
 '59cdb8c40b8b13d800034af6c332f5b900034af6c332f5b900034af6c332f5b9',
 '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
 '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9',
 '00034af6c332f5b900034af6c332f5b900034af6c332f5b900034af6c332f5b9']

class EchoClient(Protocol):
    def __init__(self):
        self.i = 0
        
    def connectionMade(self):
        print 'START:256'
        self.transport.write('START::' + base64.b64encode('LEN:256,CIPHER:DES,MODE:ECB,KEY:H@ck3rs1'))

    def dataReceived(self, recvd):

        if self.i < len(ciphertext):
            print "Writing"
            self.transport.write(binascii.unhexlify(ciphertext[self.i]))
            self.i += 1

        else:
            self.transport.write('DONE:256')
            self.transport.loseConnection()

class EchoClientFactory(ClientFactory):
    protocol = EchoClient

    def clientConnectionFailed(self, connector, reason):
        print 'connection failed:', reason.getErrorMessage()
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        print 'connection lost:', reason.getErrorMessage()
        reactor.stop()

def main():
    factory = EchoClientFactory()
    reactor.connectTCP('localhost', 8000, factory)
    reactor.run()

if __name__ == '__main__':
    main()
    
