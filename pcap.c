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
};

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
};

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
};

char* returnMacAddress(const uint8_t *macAddr) {
        char *macStr;

	macStr = (char *)malloc(20);

        sprintf(macStr, 20, "%02x:%02x:%02x:%02x:%02x:%02x", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);

        return macStr;
}

uint16_t typeConvert(uint16_t type) {
	return ((type&0xff)<<8) | ((type&0xff00)>>8);
}

char* getStringType(uint16_t intType) {
	char *returnStrings[8] = {"XNS_IDP", "IPv4", "X25_PLP", "ARP", "RARP", "NET_IPX", "NET_BIOS", "INVALID"};
	uint16_t type = typeConvert(intType);

	switch(type) {
		case 0x0600:
			return returnStrings[0];
		case 0x0800:
			return returnStrings[1];
                case 0x0805:
                        return returnStrings[2];
                case 0x0806:
                        return returnStrings[3];
                case 0x8035:
                        return returnStrings[4];
                case 0x8137:
                        return returnStrings[5];
		case 0x8191:
			return returnStrings[6];
		default:
			return returnStrings[7];
	}
}

char* returnIPAddress(uint32_t ipAddr) {
	char *ipStr;
	
	ipStr = (char *)malloc(20);

	sprintf(ipStr, 20, "%d.%d.%d.%d", ipAddr&0xff, (ipAddr&0xff00)>>8, (ipAddr&0xff0000)>>16, (ipAddr&0xff000000)>>24);

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

	ethType = getStringType(ethHdr->type);
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
		write(1, pktData+sizeof(const struct ethernetHeader)+ipHdrLen+tcpHdrLen, dataLen);
		printf("\n\n");
		return;
	}
	else {
		printf("We does not support other headers.\n\n");
		return;
	}
}

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr *header;
	const u_char *pktData;
	const u_char *packet;

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
