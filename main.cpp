/**
 * @file        main.cpp
 * @author      Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief       Main function that starts the whole process
 * @version     0.1
 * @date        10-11-2023
 * 
 * @copyright   Copyright (c) 2023
 * 
 */

#include "argcheck.h"
#include "pcap.h"
#include "parser.h"

/**
 * @brief           Main function     
 * 
 * @param argc      The number of command line arguments
 * @param argv      The array of command line arguments
 */

int main (int argc, char** argv) {
    ArgCheck argCheck(argc, argv);
    IpParse ipParse(argCheck.pref, argCheck.pref_cnt);
    PcapParse pcapParse(ipParse);
    if(argCheck.is_pcap){
        pcapParse.OpenFile(argCheck.pcap_file);
    }
    else if(argCheck.is_interface){
        pcapParse.OpenInterface(argCheck.interface);
    }
    pcapParse.PcapGet();
    getchar();
}