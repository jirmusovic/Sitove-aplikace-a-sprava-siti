/**
 * @file        pcap.h
 * @author      Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief       Heathers for pcap.cpp
 * @version     0.1
 * @date        10-11-2023
 * 
 * @copyright   Copyright (c) 2023
 * 
 */

#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#include "parser.h"
#include <ncurses.h>

class PcapParse{
    private:
    pcap_t *p_pcap;
    IpParse ipParser;

    public:
        PcapParse(IpParse ipParser);
        bool OpenFile(char *file_name);             // Open the pcap file
        bool OpenInterface(char *interface_name);   // Open a live interface for packet capture
        void PcapGet();                             // Extract IP adresses
};


#endif