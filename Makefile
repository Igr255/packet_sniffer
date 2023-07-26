CC=g++
CFLAGS= -Wall -Werror -g 
PCAP= -lpcap
NAME= ipk-sniffer

default:
	$(CC) $(NAME).cpp -o $(NAME) $(CFLAGS) $(PCAP)

clean:
	-rm $(NAME)
