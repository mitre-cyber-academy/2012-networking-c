#!/usr/bin/env python

# Created for the MITRE STEM CTF
# Author: Stephen DiCato

import base64
import pprint
import binascii
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

payloads = []

class Echo(Protocol):

    def dataReceived(self, data):
        """
        As soon as any data is received, write it back.
        """
        global payloads
        
        self.transport.write('OK')
        if data.startswith('START'):
            print "START"
            
        elif data.startswith('DONE'):
            print "DONE"
            pprint.pprint(payloads)
            
        else:
            payloads.append(data)
            
def main():
    f = Factory()
    f.protocol = Echo
    reactor.listenTCP(8000, f)
    reactor.run()

if __name__ == '__main__':
    main()
    
