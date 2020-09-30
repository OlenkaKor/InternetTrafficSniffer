#pragma once

#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);