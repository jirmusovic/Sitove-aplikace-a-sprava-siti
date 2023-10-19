#ifndef _PARSER_H_
#define _PARSER_H_

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
#include <math.h>
#include <set>
#include <vector>
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <string.h>


class IpParse{
    private:
        typedef struct
        {
            uint32_t broad_ip;
            uint32_t net_ip;
            uint8_t mask_len;
            uint32_t mask;
            char * pref;
            std::set<u_int32_t> ip;
        }parser_t;

        std::vector<parser_t> prefixes;

    public:
        IpParse();
        IpParse(char **prefixes, int pref_cnt);
        void ActualParse(uint32_t ip);
        
};


#endif