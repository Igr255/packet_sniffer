Packet sniffer

A packet sniffer program able to sniff ICMP, ICMP6, TCP and UDP packets. IPv6 extended header is not supported. Program is using PCAP library for sniffing different interfaces.

Option "sniff-only" is not included as it was only used for testing. In case you wish to use this option, run the program as "sudo ./ipk-sniffer -i [your_inreface] --sniff-only [ipv6 | ipv4 | arp]".

List of options:

-h | -help                         -  show help

-i | --interface [interface_name]  -  if used without interface_name it prints all the available interfaces otherwise it will sniff on the chosen interface

--tcp | --udp | --icmp | --arp     -  these optional arguments set which protocols will be retrieved, if none used, all of the protocols will be retrieved

-n num_of_loops                    -  sets how many frames will be retrieved

-p port_number                     -  sets the port we want to sniff on (UDP and TCP only)


How to build and run the program:

1) put "ipk-sniffer.cpp" and Makefile in the same directory
2) type "make" in the terminal
3) run the created executable as "sudo ./ipk-sniffer" 
4) run with option "-h" to show available options
5) type "make clean" to remove created executable
