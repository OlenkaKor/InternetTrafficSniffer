#include <stdio.h>
#include <packetHandler.hpp>

int main(int argc, char* argv[]) {
	int i;
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char* packet;
	struct pcap_pkthdr hdr;
	struct ether_header* eptr;    
	struct bpf_program fp;        
	bpf_u_int32 maskp;            
	bpf_u_int32 netp;

	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (descr == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}

	if (pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
	}

	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Error setting filter\n");
		exit(1);
	}

	pcap_loop(descr, -1, packetHandler, NULL);
	return 0;
}