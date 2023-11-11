/**
 * @file    pcap.cpp
 * @author Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief This source file contains the implementation of the PcapParse class, which is responsible
 *          for capturing network packets from either a pcap file or a live interface. The class extracts
 *          relevant information from captured packets, such as source IP addresses, and delegates the
 *          parsed information to an IpParse object for further analysis.
 *
 *      The PcapParse class is designed to work in conjunction with the IpParse class, providing a means
 *          to analyze DHCP traffic and generate statistical information. It utilizes the libpcap library for
 *          packet capture and parsing.
 *
 *      Key Methods:
 *          - Constructor: Initializes a PcapParse object with an associated IpParse object.
 *          - OpenFile: Opens a pcap file for reading captured packets.
 *          - PcapGet: Iterates through captured packets, extracting IP addresses and updating the associated IpParse object.
 *          - OpenInterface: Opens a live network interface for real-time packet capture.
 * @version 0.1
 * @date    10-11-2023
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "pcap.h"

PcapParse::PcapParse(IpParse ipParser) {
    this->ipParser = ipParser;
    
}

// Open a pcap file for reading
bool PcapParse::OpenFile(char *file_name){
    char errbuff[PCAP_ERRBUF_SIZE];
    p_pcap = pcap_open_offline(file_name, errbuff);
    if(p_pcap == NULL){
        printf("%s \n", errbuff);
        return false;
    }
    return true;
}

// Extract IP addresses from captured packets
void PcapParse::PcapGet(){
    this->ipParser.ConsoleAccess();
    const u_char *packet;  
    struct pcap_pkthdr header; 

    while ((packet = pcap_next(p_pcap,&header)) != NULL){
        struct ether_header *eptr = (struct ether_header *) packet;
        if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
            u_int header_len;                       // IPv4 header length
            struct ip* my_ip = (struct ip*) (packet + ETH_HLEN);
            header_len = my_ip->ip_hl*4;
            if(my_ip->ip_p == IPPROTO_UDP){
                struct in_addr *yradd = (struct in_addr *)(packet + ETH_HLEN + header_len + 8 + 16); // Udp header + yradd offset
                uint32_t options = ETH_HLEN + 8 + 240 + header_len;
                uint8_t opt;
                while((opt = *(uint8_t *) (packet + options)) != 53 && options < header.caplen){
                    uint8_t msg;
                    msg = *(uint8_t *) (packet + options + 1);
                    options += msg + 2;
                }
                if(opt == 53){
                    if(*(uint8_t *) (packet + options + 2) == 5){
                        ipParser.ActualParse(ntohl(yradd->s_addr));
                    }
                }
            }
        }
    }
    pcap_close(p_pcap);
}

// Open a live interface for packet capture
bool PcapParse::OpenInterface(char *interface_name){
    char errbuff[PCAP_ERRBUF_SIZE];
    p_pcap = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuff);
    if(p_pcap == NULL){
        printf("%s \n", errbuff);
        return false;
    }
    return true;
}