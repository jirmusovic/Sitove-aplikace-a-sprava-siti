CC=g++
CFLAGS= -c -Wall

all: dhcp-stats

dhcp-stats: main.o pcap.o argcheck.o parser.o 
	$(CC) main.o pcap.o argcheck.o parser.o -o dhcp-stats -lpcap -lncurses -lm
	rm -rf *.o

main.o: main.cpp
	$(CC) $(CFLAGS) -c $< -o $@

pcap.o: pcap.cpp pcap.h
	$(CC) $(CFLAGS) -c $< -o $@

argcheck.o: argcheck.cpp argcheck.h
	$(CC) $(CFLAGS) -c $< -o $@

parser.o: parser.cpp parser.h
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -rf *.o 