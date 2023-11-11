/**
 * @file        parser.h
 * @author      Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief       Heathers for parser.cpp
 * @version     0.1
 * @date        10-11-2023
 * 
 * @copyright   Copyright (c) 2023
 * 
 */

#ifndef _PARSER_H_
#define _PARSER_H_

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <set>
#include <vector>
#include <arpa/inet.h>
#include <ncurses.h>
#include <syslog.h>
#include <string.h>



class IpParse{
    private:
        typedef struct
        {
            uint32_t broad_ip;          // Broadcast IP in network byte order
            uint32_t net_ip;            // Network IP in network byte order
            uint8_t mask_len;           // Subnet mask length
            uint32_t mask;              // Subnet mask in network byte order
            char * pref;                // IP prefix
            uint32_t max;               // Maximum number of hosts in the subnet
            bool half = false;          // Flag indicating if allocation exceeds 50%
            std::set<u_int32_t> ip;     // Set of allocated IP addresses in the subnet
        }parser_t;

        std::vector<parser_t> prefixes;  // Vector to store information about IP prefixes

    public:
        IpParse();
        IpParse(char **prefixes, int pref_cnt);  // Constructor to parse and display information about IP prefixes
        void ActualParse(uint32_t ip);           // Function to parse an IP address and update subnet information
        
        ~IpParse();                              // Destructor to clean up resources

        
};


#endif