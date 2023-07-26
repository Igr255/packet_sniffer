#include "ipk-sniffer.h"

#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include <string>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>

/**
 * Global argument storage.
 */
static class ArgData {
    public:
        std::string interface = "none";
        std::string sniffOnly = "none";
        bool udpFlag = false;
        bool tcpFlag = false;
        bool arpFlag = false;
        bool icmpFlag = false;
        int port = -1;
        int number = 1;
} argData;

/**
 * Debugging function to see if everythong was set properly
 */

void printHelp() {
    std::cout << "Available arguments:" << std::endl;
    std::cout << " -i | --interface [interface_name]  -  if used without interface_name it prints all the available interfaces"
                 " otherwise it will sniff on the chosen interface" << std::endl;
    std::cout << " --tcp | --udp | --icmp | --arp     -  these optional arguments set which protocols will be retrieved"
                 ", if none used, all of the protocols will be retrieved" << std::endl;
    std::cout << " -n num_of_loops                    -  sets how many frames will be retrieved" << std::endl;
    std::cout << " -p port_number                     -  sets the port we want to sniff on (UDP and TCP only)" << std::endl;
    exit(0);
}

/*
void printArgClass() {
    std::cout << "DEBUG PRINT" << std::endl;
    std::cout << "interface: " + argData.interface << std::endl;
    std::cout << "udpFlag: ";
    std::cout << argData.udpFlag << std::endl;
    std::cout << "tcpFlag: ";
    std::cout << argData.tcpFlag << std::endl;
    std::cout << "arpFlag: ";
    std::cout << argData.arpFlag << std::endl;
    std::cout << "icmpFlag: ";
    std::cout << argData.icmpFlag << std::endl;
    std::cout << "port: ";
    std::cout << argData.port << std::endl;
    std::cout << "number: ";
    std::cout << argData.number << std::endl;
    std::cout << "sniffOnly: " + argData.sniffOnly << std::endl;
    printf("\n\n");
}
*/

int main(int argc, char *argv[]) {
    parseArgs(argc, argv);
    if (argData.interface == "none") {
        printAllInterfaces();
    } else  {
        setFilter();
    }

    return 0;
}


/**
 *
 * Argument parsing was done using getopt documentation
 * https://linux.die.net/man/3/getopt_long
 *
*/
int parseArgs(int argc, char *argv[]) {

    static struct option long_options[] = {
            {"interface", optional_argument, nullptr, 'i'},
            {"tcp",       no_argument,       nullptr, 't'},
            {"udp",       no_argument,       nullptr, 'u'},
            {"arp",       no_argument,       nullptr, 'a'},
            {"icmp",      no_argument,       nullptr, 'c'},
            {"sniff-only",      required_argument,       nullptr, 's'},
            {"help", no_argument, nullptr, 'h'}
    };

    int arg;
    int longindex;
    bool isNextArg = false;
    bool protocolArgUsed = false;
    std::string currentArg;

    // ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}

    while ((arg = getopt_long(argc, argv, "n::i::p::tuacs::h", long_options, &longindex)) != -1) {

        // checking if arg parameter was not ignored
        // also checking if null arg is not passed
        if (argv[optind] != nullptr) {
            if (argv[optind][0] != '-') {
                currentArg = argv[optind];
            } else {
                isNextArg = true;
            }
        }

        // setting required args
        switch (arg) {
            case 'i':
                if (!isNextArg && argv[optind] != nullptr) {
                    argData.interface = currentArg;
                }
                break;
            case 'p':
                if (isNumber(currentArg)) {
                   argData.port = std::stoi( currentArg );
                    break;
                }
                throwError(0);
                return 1;
            case 'n':
                if (isNumber(currentArg)) {
                    argData.number = std::stoi( currentArg );
                    break;
                }
                throwError(0);
                return 1;
            case 't':
                argData.tcpFlag = true;
                protocolArgUsed = true;
                break;
            case 'u':
                argData.udpFlag = true;
                protocolArgUsed = true;
                break;
            case 'a':
                argData.arpFlag = true;
                protocolArgUsed = true;
                break;
            case 'c':
                argData.icmpFlag = true;
                protocolArgUsed = true;
                break;
            case 's':
                argData.sniffOnly = currentArg;
                break;
            case 'h':
                printHelp();
                break;
            default:
                throwError(1);
                return 1;
        }
        isNextArg = false;
    }

    if (!protocolArgUsed)
        argData.icmpFlag = argData.arpFlag = argData.udpFlag = argData.tcpFlag = true;

    return 0;
}

/**
 * Helper function to check if string is a number
 */
bool isNumber(const std::string& testedString)
{
    // empty string is automatically not a number
    if (testedString.empty())
        return false;

    // iterating trough string and checking if every character is a digit
    std::string::const_iterator iterator = testedString.begin();
    while (iterator != testedString.end() && std::isdigit(*iterator))
        ++iterator;

    return true;
}

/**
 * Function handling all errors and exits if any error is thrown
 */
void throwError(int errType) {
    if (errType == 0) {
        fprintf(stderr, "Incorrect argument parameter passed");
    }
    else if (errType == 1) {
        fprintf(stderr, "Invalid argument passed");
    }
    else if (errType == 2) {
        fprintf(stderr, "Error while retrieving all interfaces");
    }
    else if (errType == 3) {
        fprintf(stderr, "Could not open device for sniffing");
    }
    else if (errType == 4) {
        fprintf(stderr, "Could not parse filter arguments");
    }
    else if (errType == 5) {
        fprintf(stderr, "Could not set filter");
    }
    else if (errType == 6) {
        fprintf(stderr, "Cannot set port if UDP or TCP is not used");
    }

    exit(1);
}

/**
 * Starts a communication with selected interface
 */
int printAllInterfaces() {
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_if_t * alldevsp;
    int res = pcap_findalldevs(&alldevsp, errBuff);

    if (res == PCAP_ERROR) {
        throwError(2);
        return 1;
    }

    // print all available interfaces
    while (alldevsp != nullptr) {
        std::cout << alldevsp->name << std::endl;

        alldevsp = alldevsp->next;
    }

    // free all interfaces
    if (alldevsp != nullptr)
        pcap_freealldevs(alldevsp);

    return 0;
}

/**
 * Starts a communication with selected interface
 */
pcap_t * openInterfaceForSniffing() {
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(argData.interface.c_str(), BUFSIZ, 1, 1000, errBuff);

    if (handle == nullptr) {
        throwError(3);
    }

    return handle;
}

/**
 * Function used for constructiong desired filter arguments based on passed arguments.
 * Next it adds a port we want to listen on.
 */
std::string setFilterArg() {
    std::string arg = "";
    bool argUsed = false;

    if (argData.icmpFlag) {
        arg += "icmp or icmp6";
        argUsed = true;
    }
    if (argData.arpFlag) {
        if (argUsed) {
            arg += " or ";
        }
        arg += "arp";
        argUsed = true;
    }
    if (argData.tcpFlag) {
        if (argUsed) {
            arg += " or ";
        }

        if (argData.port > 0) {
            arg += "(tcp and port " + std::to_string(argData.port) + ")";
        } else {
            arg += "tcp";
        }
        argUsed = true;
    }
    if (argData.udpFlag) {
        if (argUsed) {
            arg += " or ";
        }

        if (argData.port > 0) {
            arg += "(udp and port " + std::to_string(argData.port) + ")";
        } else {
            arg += "udp";
        }
    }

    return arg;
}

/**
 * Setting filter for protocols that is defined by program's arguments
 *
 * Section for filter and interface setup is inspired by:
 * https://www.tcpdump.org/pcap.html
 *
 */
void setFilter() {
    struct bpf_program fp;

    // open communication with selected interface
    pcap_t * interface = openInterfaceForSniffing();
    // set filter
    std::string filterArg =  setFilterArg();

    // try to set filter's arguments into selected interface
    if (pcap_compile(interface, &fp, filterArg.c_str(), 1, 0) == -1) {
        throwError(4);
    }

    if (pcap_setfilter(interface, &fp) == -1) {
        throwError(5);
    }

    startSniffing(interface);
}

/**
 * A simple function looping trough received packets.
 */
void startSniffing(pcap_t * interface) {
    pcap_loop(interface, argData.number, getPacket, nullptr);
    pcap_close(interface);
}

/**
 * Helper function for IP printing
 */
void printSrcDstIP(struct ip * ip){
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
}

/**
 * Helper function for IP printing
 */
void printSrcDstIP6(struct ip6_hdr * ip6){
    struct in6_addr *addrSrc = &ip6->ip6_src;

    printf("src IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            (int)addrSrc->s6_addr[0], (int)addrSrc->s6_addr[1], (int)addrSrc->s6_addr[2], (int)addrSrc->s6_addr[3],
            (int)addrSrc->s6_addr[4], (int)addrSrc->s6_addr[5], (int)addrSrc->s6_addr[6], (int)addrSrc->s6_addr[7],
            (int)addrSrc->s6_addr[8], (int)addrSrc->s6_addr[9], (int)addrSrc->s6_addr[10], (int)addrSrc->s6_addr[11],
            (int)addrSrc->s6_addr[12], (int)addrSrc->s6_addr[13], (int)addrSrc->s6_addr[14], (int)addrSrc->s6_addr[15]);

    struct in6_addr *addr2 = &ip6->ip6_dst;
    printf("dst IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           (int)addr2->s6_addr[0], (int)addr2->s6_addr[1], (int)addr2->s6_addr[2], (int)addr2->s6_addr[3],
           (int)addr2->s6_addr[4], (int)addr2->s6_addr[5], (int)addr2->s6_addr[6], (int)addr2->s6_addr[7],
           (int)addr2->s6_addr[8], (int)addr2->s6_addr[9], (int)addr2->s6_addr[10], (int)addr2->s6_addr[11],
           (int)addr2->s6_addr[12], (int)addr2->s6_addr[13], (int)addr2->s6_addr[14], (int)addr2->s6_addr[15]);
}

/**
 * Helper function for data line printing
 */
void printFrameLine(const unsigned char *dataPtr, unsigned int len, int offset) {

    // print offset in hex
    printf("0x%04x", offset);
    printf("   ");

    // print 16 or less bytes
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x ", *dataPtr);
        dataPtr++;

        // print space between 8 bytes
        if (i == 7) {
            printf("   ");
        }
    }

    // return back to start of the line
    dataPtr -= len;
    printf("   ");

    // printing actual characters (only the printable ones)
    // if they are not printable, they are replaced with a dot
    for (unsigned int i = 0; i < len; i++) {
        if (isprint(*dataPtr)) {
            printf("%c ", *dataPtr);
        } else {
            printf(". ");
        }
        dataPtr++;
    }

    printf("\n");
}

/**
 * Function used to print whole frame
 */
void printFrameData(const unsigned char *data, unsigned int len) {
    printf("\n");

    unsigned int rowLen = 16; // maximum of 16 bytes are being printed on one line
    int offset = 0;

    while (len != 0) {
        // print remaining bytes
        if (len >= rowLen) {
            printFrameLine(data, rowLen, offset);

            // prepare for next line
            // pointer + 16 so it is at the sart of next line
            data = data + 16;
            len -= 16;
        } else {
            // print remaining bytes
            printFrameLine(data, len, offset);
            break;
        }
        offset+=16;
    }
    printf("\n");
}

/**
 * If an IPv4 packet is detected, then it is separated based on supported protocols
 * In out case it is TCP, UDP and ICMP
 */
void processIPv4(const u_char * packet) {
    struct ip * ip;
    struct tcphdr * tcpHeader;
    struct udphdr * udpHeader;
    u_int ipSize;

    // the ip starts after ethernet header
    ip = (struct ip*)(packet + SIZE_ETHERNET);

    // getting ipv4 header size
    ipSize = sizeof(struct ip);

    switch (ip->ip_p) {
        case TCP_PROTOCOL:
            std::cout << "protocol: IPv4 TCP" << std::endl;
            // packet + SIZE_ETHERNET + {IP header length}
            tcpHeader = (struct tcphdr *)(packet + SIZE_ETHERNET + ipSize);
            printSrcDstIP(ip);
            printf("src port: %d\n", ntohs(tcpHeader->th_sport));
            printf("dst port: %d\n", ntohs(tcpHeader->th_dport));
            break;
        case UDP_PROTOCOL:
            std::cout << "protocol: IPv4 UDP" << std::endl;
            udpHeader = (struct udphdr *)(packet + SIZE_ETHERNET + ipSize);
            printSrcDstIP(ip);
            printf("src port: %d\n", ntohs(udpHeader->uh_sport));
            printf("dst port: %d\n", ntohs(udpHeader->uh_dport));
            break;
        case ICMP_PROTOCOL:
            std::cout << "protocol: IPv4 ICMP" << std::endl;
            // the data inside icmp header is not needed
            //struct icmphdr * icmpHeader;
            //icmpHeader = (struct icmphdr *)(packet + SIZE_ETHERNET + ipSize);
            printSrcDstIP(ip);
            break;
        default:
            break;
    }
}

/**
 * If an IPv6 packet is detected, then it is separated based on supported protocols
 * In out case it is TCP, UDP and ICMP
 */
void processIPv6(const u_char * packet) {
    struct ip6_hdr * ip6;
    struct tcphdr * tcpHeader;
    struct udphdr * udpHeader;
    u_int ipSize;

    // the ip starts after ethernet header
    ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET);

    // ipv6 header size
    ipSize = sizeof(struct ip6_hdr);

    switch (ip6->ip6_nxt) {
        case TCP_PROTOCOL:
            std::cout << "protocol: IPv6 TCP" << std::endl;
            // packet + SIZE_ETHERNET + {IP header length}
            tcpHeader = (struct tcphdr *)(packet + SIZE_ETHERNET + ipSize);
            printSrcDstIP6(ip6);
            printf("src port: %d\n", ntohs(tcpHeader->th_sport));
            printf("dst port: %d\n", ntohs(tcpHeader->th_dport));
            break;
        case UDP_PROTOCOL:
            std::cout << "protocol: IPv6 UDP" << std::endl;
            udpHeader = (struct udphdr *)(packet + SIZE_ETHERNET + ipSize);
            printSrcDstIP6(ip6);
            printf("src port: %d\n", ntohs(udpHeader->uh_sport));
            printf("dst port: %d\n", ntohs(udpHeader->uh_dport));
            break;
        case ICMP6_PROTOCOL:
            std::cout << "protocol: IPv6 ICMP6" << std::endl;
            // the data inside icmp header are not needed
            //struct icmp6_hdr * icmpHeader;
            //icmpHeader = (struct icmp6_hdr *)(packet + SIZE_ETHERNET + ipSize);
            printSrcDstIP6(ip6);
            break;
        default:
            break;
    }
}

/**
 * Function used to print defined time stamp in YYYY-MM-DDTHH:MM:SS.MS+Offset format
 * Inspired by: https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
 */
void printTimeStamp(timeval timeStamp) {
    printf("-----------------------------------------------------------------------------------------------\n\n");

    struct tm *realTime;
    char tmpBuffer[TIME_LEN];

    // change to a supported time format
    realTime = localtime(&(timeStamp.tv_sec));

    strftime(tmpBuffer, sizeof tmpBuffer, "%Y-%m-%dT%H:%M:%S", realTime);
    printf("timestamp: %s.%03d+01:00\n", tmpBuffer, (int)timeStamp.tv_usec/1000);
}

/**
 * Helper function used to print bytes of MAC adresses
 * by parsing them into specified string
 */
void printMacAddress(unsigned char	h_source[ETH_ALEN], unsigned char h_dest[ETH_ALEN]) {
    printf("src MAC: %02X-%02X-%02X-%02X-%02X-%02X\n",
           h_source[0], h_source[1], h_source[2], h_source[3], h_source[4], h_source[5]);

    printf("dst MAC: %02X-%02X-%02X-%02X-%02X-%02X\n",
           h_dest[0], h_dest[1], h_dest[2], h_dest[3], h_dest[4], h_dest[5]);
}

/**
 * Function prcessiong ARP packet
 */
void processArp(const u_char * packet) {
    struct ether_arp * arpHeader;
    arpHeader = (struct ether_arp *)(packet + SIZE_ETHERNET);
    // print mac addresses stored inside ARP packet
    printMacAddress(arpHeader->arp_sha, arpHeader->arp_tha);
}

/**
 * Helper function used to print frame length
 */
void printFrameSize(const struct pcap_pkthdr *header) {
    printf("frame length: %i bytes\n", header->caplen);
}

/**
 * Main function used to handle incoming packets.
 * Calls helper function based on used protocol.
 */
void getPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // retrieving ethernet header from packet
    // https://stackoverflow.com/questions/50652050/what-is-the-difference-between-ether-header-and-ethhdr
    // using ethhdr instead od ether_header because it is outdated
    auto * ethernetHeader = (struct ethhdr *)(packet);
    int packetType = ntohs(ethernetHeader->h_proto);

    switch (packetType) {
        case IPV4_PACKET:
            if (argData.sniffOnly == "ipv4" || argData.sniffOnly == "none") {
                printTimeStamp(header->ts);
                printMacAddress(ethernetHeader->h_source, ethernetHeader->h_dest);
                printFrameSize(header);

                processIPv4(packet);
                printFrameData(packet, header->caplen);
            }
            break;
        case IPV6_PACKET:
            if (argData.sniffOnly == "ipv6" || argData.sniffOnly == "none") {
                printTimeStamp(header->ts);
                printMacAddress(ethernetHeader->h_source, ethernetHeader->h_dest);
                printFrameSize(header);

                processIPv6(packet);
                printFrameData(packet, header->caplen);
            }
            break;
        case ARP_PACKET:
            if (argData.sniffOnly == "arp" || argData.sniffOnly == "none") {
                printTimeStamp(header->ts);
                printMacAddress(ethernetHeader->h_source, ethernetHeader->h_dest);
                std::cout << "protocol: ARP" << std::endl;
                printFrameSize(header);

                processArp(packet);
                printFrameData(packet, header->caplen);
            }
            break;
        default:
            break;
    }
}