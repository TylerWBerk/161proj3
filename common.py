#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = """GET /search/?q=falun+gong HTTP/1.1\r\nConnection: keep-alive\r\nHost: www.google.com\r\n\r\n"""

# A couple useful functions that take scapy packets
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
    return ICMP in p

def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()
        
        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.
        
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        p = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet.
    def send_pkt(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80,ipid=None,
                 dip=None,debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        p = ip/t
        if payload:
            p = ip/t/payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e/p], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return p


    # Has an automatic 5 second timeout.
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation
    def evade(self, target, msg, ttl):
        #similar to slide 15 of lecture 18, will split message into single characters
        #and then insert fake characters with the shorter ttl between each of them, send all of these packets
        #then get the payload from the server
        chars = list(msg)
        fakes = list("memes")
        rsport = random.randint(2000, 30000)
        syn = self.send_pkt(flags = "S", sport = rsport)
        synack = self.get_pkt()
        while(synack != None and synack[TCP].sport != syn[TCP].dport):
            synack = self.get_pkt()
        #now that you have synackd, ack and then send long payload split into 1 byte packets
        ack = self.send_pkt(flags = "A", sport = rsport, dport = synack[TCP].sport, seq = synack[TCP].ack, ack = synack[TCP].seq + 1)
        #now loop through chars
        for i in range(len(chars)):
            newReal = self.send_pkt(payload = chars[i], flags = "A", sport = rsport, dport = synack[TCP].sport, seq = synack[TCP].ack + i, ack = synack[TCP].seq + 1)
            newFake = self.send_pkt(payload = fakes[i%len(fakes)], ttl = ttl, flags = "A", sport = rsport,
                                    dport = synack[TCP].sport, seq = synack[TCP].ack + i, ack = synack[TCP].seq + 1)

        #now that you have looped through, check for packet for 5 seconds
        timeout = time.time() + 5
        packetList = []
        payload = []
        while 1:
            rp = self.get_pkt(max(0, timeout - time.time()))
            if not rp:
                break
            if(not isICMP(rp)):
                packetList.append(rp)
        for x in packetList:
            if 'Raw' in x:
                payload.append(x['Raw'].load)
        return ''.join(payload)

        
    # Returns "DEAD" if server isn't alive,
    # "LIVE" if teh server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):
        # self.send_msg([triggerfetch], dst=target, syn=True)

        #choose random source port
        rsport = random.randint(2000, 30000)
        #send syn packet
        self.send_pkt(flags = "S", sport = rsport)
        #check if received a response
        synack = self.get_pkt()
        if(synack == None):
            return "DEAD"
        #now u have received a response, send ack
        ack = self.send_pkt(flags = "A", sport = rsport, dport = synack[TCP].sport, seq = synack[TCP].ack, ack = synack[TCP].seq + 1)
        #now send payload
        payload = self.send_pkt(payload = triggerfetch, flags = "P", sport = rsport, dport = synack[TCP].sport, seq = ack[TCP].seq, ack = ack[TCP].ack)
        #now check what you receive in response, once queue is emptied, if resets missing, "LIVE", if they are there, "FIREWALL
        while True:
            pckt = self.get_pkt()
            if(pckt == None):
                return "LIVE"
            if(isRST(pckt)):
                return "FIREWALL"

    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F 
    # if there is a RST back for that particular request
    def traceroute(self, target, hops):
        output1 = []
        output2 = []
        for i in range(hops):
            #at each hop, handshake
            rsport = random.randint(2000, 30000)
            syn = self.send_pkt(flags = "S", sport = rsport)
            synack = self.get_pkt()
            while(synack != None and synack[TCP].sport != syn[TCP].dport):
                synack = self.get_pkt()
            if(synack == None):
                output1.append(None)
                output2.append(False)
                continue

            ack = self.send_pkt(flags = "A", sport = rsport, dport = synack[TCP].sport, seq = synack[TCP].ack, ack = synack[TCP].seq + 1)
            #now send the payload 3 times
            for j in range(3):
                self.send_pkt(payload = triggerfetch,  ttl = i + 1, flags = "PA", sport = syn[TCP].sport, dport = synack[TCP].sport, seq = ack[TCP].seq, ack = ack[TCP].ack)
            #now check if there is a reset in the queue, get the ip of the hop, as well as empty the queue for the next step
            hasRST = False
            hopIP = None
            wasRST = False
            while(True):
                pckt = self.get_pkt()
                if(pckt == None):
                    break
                if(isRST(pckt) and pckt[TCP].dport == rsport):
                    hasRST = True
                    wasRST = True
                    #hopIP = pckt[IP].src
                if(isTimeExceeded(pckt)):
                    hopIP = pckt[IP].src
            output1.append(hopIP)
            output2.append(hasRST)

        return (output1, output2)
