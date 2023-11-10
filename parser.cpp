/**
 * @file parser.cpp
 * @author Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief 
 * @version 0.1
 * @date 10-11-2023
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "parser.h"

IpParse::IpParse(char **prefixes_array, int pref_array_cnt) {
    initscr();
    printw("IP-Prefix Max-hosts Allocated addresses Utilization");
    for(int i = 0; i < pref_array_cnt; i++){
        parser_t subnet;
        subnet.pref = prefixes_array[i];
        char *ptr = strtok (prefixes_array[i], "/");
        int ip;
        inet_pton(AF_INET, ptr, &ip);
        subnet.net_ip = ntohl(ip);
        subnet.mask_len = atoi(strtok(NULL, "/"));
        if(subnet.mask_len == 0){
            subnet.mask = 0;
        } else {
            subnet.mask = ~0<<(32-subnet.mask_len);
        }
        subnet.broad_ip = subnet.net_ip|(~subnet.mask);
        subnet.max = pow(2, 32-subnet.mask_len) - 2;
        prefixes.push_back(subnet);
        double util = 100 * subnet.ip.size()/(double)subnet.max;
        double full = 50.00;
        if((full-util) <= 0){
        }
        mvprintw(i+1, 0, "%s/%d %u %u %.2f%%", prefixes_array[i], subnet.mask_len, subnet.max, subnet.ip.size(), util);
        
    }
    refresh();
}

IpParse::IpParse() = default;

void IpParse::ActualParse(uint32_t ip){
    for(long unsigned int i = 0; i < prefixes.size(); i++){
        parser_t * subnet = &prefixes.at(i);
        if((ip & subnet->mask) == subnet->net_ip && (subnet->net_ip != ip) && (ip != subnet->broad_ip)){
            subnet->ip.insert(ip);
            double util = 100 * subnet->ip.size()/(double)subnet->max;
            double full = 50.00;
            if((full-util) <= 0){
            }
            mvprintw(i+1, 0, "%s/%d %u %u %.2f%%", subnet->pref, subnet->mask_len, subnet->max, subnet->ip.size(), util);

        }
    }
            refresh();
}


IpParse::~IpParse(){
    endwin();
}
