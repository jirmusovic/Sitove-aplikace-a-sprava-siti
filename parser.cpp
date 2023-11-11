/**
 * @file    parser.cpp
 * @author  Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief   Implementation of classes for DHCP statistics and IP prefix management.
 *
 *          This file contains the implementation of the `IpParse` class, which is responsible
 *          for parsing and managing DHCP statistics related to IP prefixes. It utilizes the
 *          `parser_t` structure to represent information about IP subnets, including network
 *          IP, subnet mask, broadcast IP, maximum hosts, allocated addresses, and utilization.
 *
 *          The `IpParse` class has two primary functions:
 *           1. IpParse: Parses provided IP prefixes, initializes subnet information, and
 *              displays a summary on the screen.
 *           2. ActualParse: Takes an IP address as input, updates the corresponding subnet
 *              information, and displays the updated summary on the screen.
 *
*              The program uses the ncurses library for text-based user interface and syslog for
*              logging noteworthy events, such as subnet allocations exceeding 50%.
 * @version     0.1
 * @date        10-11-2023
 * 
 * @copyright   Copyright (c) 2023
 * 
 */

#include "parser.h"

IpParse::IpParse(char **prefixes_array, int pref_array_cnt) {
    // Initialization of system log process
    setlogmask(LOG_UPTO(LOG_NOTICE));
    initscr();
    // Loops through each IP prefix
    for(int i = 0; i < pref_array_cnt; i++){
        parser_t subnet;
        // Parse and initialize subnet information
        subnet.pref = prefixes_array[i];
        char *ptr = strtok(prefixes_array[i], "/");
        int ip;
        inet_pton(AF_INET, ptr, &ip);
        subnet.net_ip = ntohl(ip);
        subnet.mask_len = atoi(strtok(NULL, "/"));

        // Calculate subnet mask, broadcast IP, and maximum hosts
        if(subnet.mask_len == 0){
            subnet.mask = 0;
        } else {
            subnet.mask = ~0<<(32-subnet.mask_len);
        }
        subnet.broad_ip = subnet.net_ip|(~subnet.mask);
        subnet.max = pow(2, 32-subnet.mask_len) - 2;
        subnet.net_ip &= subnet.mask;
        // Push subnet info to the prefix vector
        prefixes.push_back(subnet);
        
    }
    
}


void IpParse::ConsoleAccess(){
        // Display header for the subnet information
    printw("IP-Prefix Max-hosts Allocated addresses Utilization");
    for(u_long i = 0; i < prefixes.size(); i++){
        mvprintw(i+1, 0, "%s/%d %u %u 0.0%%", prefixes.at(i).pref, prefixes.at(i).mask_len, prefixes.at(i).max, prefixes.at(i).ip.size());
    }
    refresh();
}

IpParse::IpParse() = default;

void IpParse::ActualParse(uint32_t ip){
    // Loop through each subnet and check if the provided IP belongs to it
    for(long unsigned int i = 0; i < prefixes.size(); i++){
        parser_t * subnet = &prefixes.at(i);
        if((ip & subnet->mask) == subnet->net_ip && (subnet->net_ip != ip) && (ip != subnet->broad_ip)){
            // Update the subnet information with the allocated IP
            subnet->ip.insert(ip);

            // Calculate utilization and display updated information on the screen
            double util = 100 * subnet->ip.size()/(double)subnet->max;
            if(subnet->ip.size() >= subnet->max/2.0 && !subnet->half ){
                subnet->half = true;
                openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL0);
                syslog (LOG_NOTICE, "prefix %s/%d exceeded 50%% of allocations\n", subnet->pref, subnet->mask_len);
                closelog();
            }
            mvprintw(i+1, 0, "%s/%d %u %u %.2f%%", subnet->pref, subnet->mask_len, subnet->max, subnet->ip.size(), util);
        }
    }
            refresh();
}


// Clean up
IpParse::~IpParse(){
    endwin();
}
