#include "packetHandler.hpp"

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	static int count = 1;
	struct mac_filter* p = (struct mac_filter*)packet;
	const unsigned int data_len = (pkthdr->len - sizeof * p);
	const u_char* data = (packet + sizeof * p);
	int i = 0;

	printf("Number: %d\n", count);

	printf("Type: %04hx\n", p->ether_type);

	printf(
		"Destination: %02X:%02X:%02X:%02X:%02X:%02X\n",
		p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
		p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]
	);

	printf(
		"Sender:      %02X:%02X:%02X:%02X:%02X:%02X\n",
		p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
		p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]
	);

	for (i = 0; i < data_len; i++) {
		printf("  %02x", data[i] & 0xff);
	}
	printf("\n");
	count++;
}