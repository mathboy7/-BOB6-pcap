all: pcap.o
        gcc -o pcap pcap.o -lpcap
