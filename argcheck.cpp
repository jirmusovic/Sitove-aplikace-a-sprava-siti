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
    for(int i = 0; i < pref_cnt; i++){
        printf("pref: %s \n", pref[i]);
    }
}