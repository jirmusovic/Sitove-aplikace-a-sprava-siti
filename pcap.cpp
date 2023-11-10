/**
 * @file pcap.cpp
 * @author Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief 
 * @version 0.1
 * @date 10-11-2023
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "pcap.h"

PcapParse::PcapParse(IpParse ipParser) {
    this->ipParser = ipParser;
}

bool PcapParse::OpenFile(char *file_name){
    char errbuff[PCAP_ERRBUF_SIZE];
    p_pcap = pcap_open_offline(file_name, errbuff);
    if(p_pcap == NULL){
        printf("%s \n", errbuff);
        return false;
    }
    return true;
}

//! pcap_compile, pcap_setfilter 

void PcapParse::PcapGet(){
    const u_char *packet;  
    struct pcap_pkthdr header; 

    while ((packet = pcap_next(p_pcap,&header)) != NULL){
        struct ether_header *eptr = (struct ether_header *) packet;
        if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
            u_int header_len;                       // IPv4 header length
            struct ip* my_ip = (struct ip*) (packet + ETH_HLEN);
            header_len = my_ip->ip_hl*4;
            if(my_ip->ip_p == IPPROTO_UDP){
                struct in_addr *yradd = (struct in_addr *)(packet + ETH_HLEN + header_len + 8 + 16); //udp hdr + yradd offset
                ipParser.ActualParse(ntohl(yradd->s_addr));
            }
        }
    }
}

bool PcapParse::OpenInterface(char *interface_name){
    char errbuff[PCAP_ERRBUF_SIZE];
    p_pcap = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuff);
    if(p_pcap == NULL){
        printf("%s \n", errbuff);
        return false;
    }
    return true;
}