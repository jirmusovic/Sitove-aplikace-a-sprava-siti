#include "parser.h"

IpParse::IpParse(char **prefixes_array, int pref_array_cnt) {
    for(int i = 0; i < pref_array_cnt; i++){
        parser_t subnet;
        subnet.pref = prefixes_array[i];
        char *ptr = strtok (prefixes_array[i], "/");
        int ip;
        inet_pton(AF_INET, ptr, &ip);
        //printf("%x\n", ntohl(ip));
        subnet.net_ip = ntohl(ip);
        subnet.mask_len = atoi(strtok(NULL, "/"));
        subnet.mask = ~0<<(32-subnet.mask_len);
        subnet.broad_ip = subnet.net_ip|(~subnet.mask);
        prefixes.push_back(subnet);
    }
}

IpParse::IpParse() = default;

void IpParse::ActualParse(uint32_t ip){
    for(parser_t subnet: prefixes){
        if((ip & subnet.mask) == subnet.net_ip && (subnet.net_ip != ip) && (ip != subnet.broad_ip)){
            subnet.ip.insert(ip);
            printf("ip: %x belongs to subnet %s \n", ip, subnet.pref);
        }
    }
}



