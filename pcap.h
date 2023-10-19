#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <err.h>  
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#include "parser.h"

class PcapParse{
    private:
    pcap_t *p_pcap;
    IpParse ipParser;

    public:
        PcapParse(IpParse ipParser);
        bool OpenFile(char *file_name);
        bool OpenInterface(char *interface_name);
        void PcapGet();
        //! todo: pcap compile to add filter
};


#endif