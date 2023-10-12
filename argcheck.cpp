#include "argcheck.h"

int optcheck(int argc, char* argv[]){
    int opt;
    bool is_pcap, is_interface;
    char *interface, *pcap_file;

    is_pcap = false;
    is_interface = false;

    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
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
}