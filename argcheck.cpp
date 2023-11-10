/**
 * @file argcheck.cpp
 * @author Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief 
 * @version 0.1
 * @date 10-11-2023
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "argcheck.h"


ArgCheck::ArgCheck() = default;

ArgCheck::ArgCheck(int argc, char* argv[]){
    int opt;

    is_pcap = false;
    is_interface = false;

    while ((opt = getopt(argc, argv, "hr:i:")) != -1) {
        switch (opt) {
        case 'h':
            printf("./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]");
            break;
        case 'r':
            pcap_file = optarg;
            is_pcap = true;
            break;
        case 'i':
            interface = optarg;
            is_interface = true;
            break;
        }
    }

    pref= &argv[optind];
    pref_cnt = argc - optind;

//! todo: regex pro ip
    // char ip_regex;
    // "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/(30|([0-2]?[0-9]?))"
    // if(*pref != &ip_regex){
        
    // }
}