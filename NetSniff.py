#!/usr/bin/env python
# ------------------------------------------------------------------------
# The MIT License (MIT)
# Copyright (c) 2015 Hassan Alsaffar <hassan_alsaffar@outlook.com>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This packet sniffer uses a raw socket to listen for packets in transit with 
# eth type of 0x800 -> TCP and UDP packets
#
# Note: need root permissions to be able to access the raw sockets.
# -------------------------------------------------------------------------

# ###################################
#           I M P O R T S
# ###################################
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, inet_ntoa, htons, PF_PACKET
from struct import *
from binascii import hexlify as readHex

# ###################################
#         F U N C T I O N S
# ###################################
def receivePacket(netSocket):

	PCAP = {} #Packet Captured

	#receive a message from a socket
	packet = netSocket.recvfrom(65565)
        packet = packet[0] 

	#Layer 2 - Link Layer (Ethernet Header)
	ethHeader = packet[0:14]
	ethHeader = unpack(">6s6s2s", ethHeader)
	PCAP["Source Ethernet Address"] = readHex(ethHeader[1])
	PCAP["Destination Ethernet Address"] = readHex(ethHeader[0])
        PCAP["Ethernet Type"] = readHex(ethHeader[2])

    #Layer 3 - TCP/IP (IP Header and TCP header)
	ipHeader = packet[14:34]
	ipHeader = unpack(">1s1s2s2s2s1s1s2s4s4s", ipHeader)
	protocolNum = readHex(ipHeader[6])
	PCAP["Source IP Address"] = inet_ntoa(ipHeader[8])
	PCAP["Destination IP Address"] = inet_ntoa(ipHeader[9])
    	
	#Layer 4 - Transport Layer 
	if protocolNum == "06": 
		PCAP["Protocol"] = "TCP (%s)" % (protocolNum)
        transportLayerHeader = packet[34:54]
		transportLayerHeader = unpack(">HHLLBBHHH", transportLayerHeader)
        PCAP["Data"] = packet[54:]
		PCAP["Source Port"]= transportLayerHeader[0]
        PCAP["Destination Port"] = transportLayerHeader[1]
		PCAP["SEQ"] = transportLayerHeader[2]
		PCAP["ACK"] = transportLayerHeader[3]
		PCAP["Offset"] = transportLayerHeader[4]
		flag = transportLayerHeader[5]
		if flag == 1: 
			flag = "FIN"
		elif flag == 2:
			flag = "SYN"
		elif flag == 4:
			flag = "RST"
		elif flag == 8: 
			flag == "PSH"
		elif flag == 16:
			flag = "ACK"
		elif flag == 32:
			flag = "URG"
		PCAP["flag"] = flag
		PCAP["Window"] = transportLayerHeader[6]
		PCAP["Checksum"] = transportLayerHeader[7]
	
	elif protocolNum == "11":
		PCAP["Protocol"] = "UDP (%s)" % (protocolNum)
        transportLayerHeader = packet[34:42]
        transportLayerHeader = unpack(">HHHH", transportLayerHeader)
        PCAP["Data"] = packet[42:]
		PCAP["Source Port"]= transportLayerHeader[0]
        PCAP["Destination Port"] = transportLayerHeader[1]
		PCAP["Length"] = transportLayerHeader[2]
        PCAP["Checksum"] = transportLayerHeader[3]

	return PCAP

 
# ###################################
#     M A I N    P R O G R A M
# ###################################
if __name__=='__main__':

	#Create a socket
	netSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))
	
	ctr = 1 #set packet counter
	
	#receive a packet
	while True:
		
		#Capture & Parse Packet:
        PCAP = receivePacket(netSocket)

		print "=" * 30 + "Packet Captured No. %s" % (ctr) + "=" * 30 + "\n"
		print "[*] Src. MAC: %s -> Dest. MAC: %s" % (PCAP["Source Ethernet Address"], PCAP["Destination Ethernet Address"])
        print "[*] Protocol: %s" % (PCAP["Protocol"])
        print "[*] Src IP: %s:%s -> Dest. IP: %s:%s" % (PCAP["Source IP Address"], PCAP["Source Port"], PCAP["Destination IP Address"], PCAP["Destination Port"])
        if "TCP" in PCAP["Protocol"]:
			print "[*] Seq. Number: %s \t Ack Number: %s \tFlag: %s" % (PCAP["SEQ"], PCAP["ACK"], PCAP["flag"])
		print "[*] Data/Payload:"
		print "    %s" % (PCAP["Data"])
		print "\n"
		ctr += 1
