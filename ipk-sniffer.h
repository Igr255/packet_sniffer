//
// Created by Igor Hanus on 11. 4. 2022.
//

#ifndef IPK2_IPK_SNIFFER_H
#define IPK2_IPK_SNIFFER_H


#include <iostream>
#include <pcap/pcap.h>

// Protocols hex values converted to int
#define IPV4_PACKET 2048
#define ARP_PACKET 2054
#define IPV6_PACKET 34525

// ethernet header is always 14 bytes
#define SIZE_ETHERNET 14

// IP protocols
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define ICMP_PROTOCOL 1
#define ICMP6_PROTOCOL 58

// defined size for buffer used to store packet times
#define TIME_LEN (sizeof "2021-03-19T18:42:52.362+01:00")

int parseArgs(int argc, char *argv[]);
bool isNumber(const std::string& testedString);
void throwError(int errType);
int printAllInterfaces();
void setFilter();
pcap_t * openInterfaceForSniffing();
void startSniffing(pcap_t * interface);
void getPacket(u_char *args, const struct pcap_pkthdr *header,
               const u_char *packet);

#endif //IPK2_IPK_SNIFFER_H
