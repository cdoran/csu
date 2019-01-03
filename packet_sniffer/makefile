all: sniffer.c sniffer.h
	gcc sniffer.c -o sniffer -lpcap 

sniffer: sniffer.c sniffer.h
	gcc sniffer.c -o sniffer -lpcap

clean:
	rm sniffer
