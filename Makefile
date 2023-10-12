CC=g++
CFLAGS= -c -Wall

all: prog

prog: main.o pcap.o argcheck.o parser.o
	$(CC) main.o pcap.o argcheck.o parser.o -o prog

main.o: main.cpp
	$(CC) $(CFLAGS) main.cpp

pcap.o: pcap.cpp
	$(CC) $(CFLAGS) pcap.cpp

argcheck.o: argcheck.cpp
	$(CC) $(CFLAGS) argcheck.cpp

parser.o: parser.cpp
	$(CC) $(CFLAGS) parser.cpp

clean:
	rm -rf *.o 