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
        //printf("%x\n", ntohl(ip));
        subnet.net_ip = ntohl(ip);
        subnet.mask_len = atoi(strtok(NULL, "/"));
        subnet.mask = ~0<<(32-subnet.mask_len);
        subnet.broad_ip = subnet.net_ip|(~subnet.mask);
        subnet.max = pow(2, 32-subnet.mask_len) - 2;
        prefixes.push_back(subnet);
        double util = 100 * subnet.ip.size()/(double)subnet.max;
        mvprintw(i+1, 0, "%s %u %u %.2f%%", prefixes_array[i], subnet.max, subnet.ip.size(), util);
    }
    refresh();
}

IpParse::IpParse() = default;

void IpParse::ActualParse(uint32_t ip){
    for(int i = 0; i < prefixes.size(); i++){
        parser_t * subnet = &prefixes.at(i);
        if((ip & subnet->mask) == subnet->net_ip && (subnet->net_ip != ip) && (ip != subnet->broad_ip)){
            subnet->ip.insert(ip);
            //printf("size %d", subnet->ip.size());
            double util = 100 * subnet->ip.size()/(double)subnet->max;
            mvprintw(i+1, 0, "%s %u %u %.2f%%", subnet->pref, subnet->max, subnet->ip.size(), util);
            //move(i+2,0);
            //getch();
        }
    }
            refresh();
}


IpParse::~IpParse(){
    endwin();
}
