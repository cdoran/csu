all: fsniffer.c fsniffer.h
	gcc fsniffer.c -o fsniffer -lpcap -Wall

sniffer: fsniffer.c fsniffer.h
	gcc fsniffer.c -o fsniffer -lpcap -Wall 

clean:
	rm fsniffer
