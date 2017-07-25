#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

struct ethernetHeader {
	uint8_t dMac[6];
	uint8_t sMac[6];
	uint16_t type;
}__attribute__((packed));

struct ipHeader {
	uint8_t basicInfo;
	uint8_t typeOfService;
	uint16_t totalLen;
	uint16_t id;
	uint16_t fragmentOffset;
	uint8_t ttl;
	uint8_t protocol; // ICMP 1, IGMP 2, TCP 6, UDP 17
	uint16_t checksum;
	uint32_t sIP;
	uint32_t dIP;
}__attribute__((packed));

struct tcpHeader {
	uint16_t sPort;
	uint16_t dPort;
	uint32_t sequenceNumber;
	uint32_t acknowledgenUMBER;
	uint8_t basicInfo;
	uint8_t tcpFlags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgentPointer;
}__attribute__((packed));

void printPacketInfo(struct pcap_pkthdr *header, const u_char *pktData); // parse packet info and print it
uint16_t typeConvert(uint16_t type); // convert little endian -> number
char* returnMacAddress(const uint8_t *macAddr); // return mac address string
char* getEthHeaderType(uint16_t intType);
char* returnIPAddress(uint32_t ipAddr);
char* getProtocolType(uint8_t intType);

void hexDump(char *desc, void *addr, int len);

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr *header;
	const u_char *pktData;
	const u_char *packet;

	if(argc != 2) {
		printf("Usage: ./pcap [dev_name]\n");
		return -1;
	}

	if(argv[1] == NULL) {
		fprintf(stderr, "Couldn't find default device!\n");
		return 2;
	}

	printf("Device: %s\n", argv[1]);

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return 2;
	}

	while(1) {
		if(pcap_next_ex(handle, &header, &pktData) == -1) {
			printf("Error occured!\n");
		}
		printPacketInfo(header, pktData);
	}
	pcap_close(handle);
	return 0;
}	

char* returnMacAddress(const uint8_t *macAddr) {
	char *macStr;

	macStr = (char *)malloc(20);

	sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);

	return macStr;
}

uint16_t typeConvert(uint16_t type) {
	return ((type&0xff)<<8) | ((type&0xff00)>>8);
}

char* getEthHeaderType(uint16_t intType) {
	uint16_t type = typeConvert(intType);

	switch(type) {
		case 0x0600:
			return "XNS_IDP";
		case 0x0800:
			return "IPv4";
		case 0x0805:
			return "X25_PLP";
		case 0x0806:
			return "ARP";
		case 0x8035:
			return "RARP";
		case 0x8137:
			return "NET_IPX";
		case 0x8191:
			return "NET_BIOS";
		default:
			return "INVALID";
	}
}

char* returnIPAddress(uint32_t ipAddr) {
	char *ipStr;

	ipStr = (char *)malloc(20);

	sprintf(ipStr, "%d.%d.%d.%d", ipAddr&0xff, (ipAddr&0xff00)>>8, (ipAddr&0xff0000)>>16, (ipAddr&0xff000000)>>24);

	return ipStr;
}

char* getProtocolType(uint8_t intType) {
	// ICMP 1, IGMP 2, TCP 6, UDP 17
	switch(intType) {
		case 1:
			return "ICMP";
		case 2:
			return "IGMP";
		case 6:
			return "TCP";
		case 17:
			return "UDP";
		default:
			return "INVALID";
	}
}

void printPacketInfo(struct pcap_pkthdr *header, const u_char *pktData) {
	const struct ethernetHeader *ethHdr;
	char *dMac, *sMac, *ethType;
	uint16_t type;

	const struct ipHeader *ipHdr;
	char *dIP, *sIP, *protocolType;
	uint32_t ipHdrLen, packetLen;

	const struct tcpHeader *tcpHdr;
	uint16_t sPort, dPort;
	uint16_t tcpHdrLen, dataLen;

	if(header->len == 0) {
		printf("No data captured.\n");
		return;
	}

	puts("========== Captured Packet ==========");	
	ethHdr = (const struct ethernetHeader *)pktData;

	dMac = returnMacAddress(ethHdr->dMac);
	sMac = returnMacAddress(ethHdr->sMac);
	printf("Destination Mac address: [%s]\n", dMac);
	printf("Source MAC address: [%s]\n", sMac);

	ethType = getEthHeaderType(ethHdr->type);
	printf("Protocol type: %s\n\n", ethType);

	if(strcmp(ethType, "IPv4")) {
		printf("Protocol type: %s\n", ethType);
		printf("We does not support this type.\n\n");
		return;
	}

	ipHdr = (const struct ipHeader *)(pktData+sizeof(const struct ethernetHeader));
	ipHdrLen = (ipHdr->basicInfo&0xf) * 4;
	packetLen = typeConvert(ipHdr->totalLen)-ipHdrLen;

	dIP = returnIPAddress(ipHdr->dIP);
	sIP = returnIPAddress(ipHdr->sIP);
	printf("IP Header Length: %d\n", ipHdrLen);
	printf("Destination IP Address: [%s]\n", dIP);
	printf("Source IP Address: [%s]\n", sIP);

	protocolType = getProtocolType(ipHdr->protocol);
	printf("Protocl type: %s\n\n", protocolType);

	if(!strcmp(protocolType, "TCP")) {
		tcpHdr = (const struct tcpHeader *)(pktData+sizeof(const struct ethernetHeader)+ipHdrLen);
		tcpHdrLen = ((tcpHdr->basicInfo&0xf0)>>4) * 4;
		dataLen = packetLen-tcpHdrLen;

		printf("TCP Header Length: %d\n", tcpHdrLen);
		printf("Data Length: %d\n\n", dataLen);

		dPort = typeConvert(tcpHdr->dPort);
		sPort = typeConvert(tcpHdr->sPort);
		printf("Destination Port: [%d]\n", dPort);
		printf("Source Port: [%d]\n\n", sPort);

		printf("Data: ");
		hexDump("Packet Data", (void *)(pktData+sizeof(const struct ethernetHeader)+ipHdrLen+tcpHdrLen), dataLen);
		printf("\n\n");
		return;
	}
	else {
		printf("We does not support other headers.\n\n");
		return;
	}
}

void hexDump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf ("%s:\n", desc);

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n",len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf ("  %s\n", buff);

			// Output the offset.
			printf ("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf ("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf ("  %s\n", buff);
}
