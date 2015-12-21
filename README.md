# NetSniff: 
A simple and  basic network packets sniffer for Linux systems developed using Raw Sockets library implemented in Python 2.7. It displays all the packets that are transmitted on the local network and gives basic detailed information about the Ethernet and TCP/IP headers in the packet in addition to the Data payload (raw data). 

NetSniff will only capture packets with ethernet type of 0x800; meaning that it would only show packets that are Internet Protocol version 4 (IPv4) based (TCP or UDP packets only). Features to support various protocols such as ICMP, ARP, etc is a future work. 

# NetSniff in Action: 
![alt tag](https://i.imgur.com/lWLu3Qk.jpg?1)
