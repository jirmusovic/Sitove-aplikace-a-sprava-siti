#include "argcheck.h"
#include "pcap.h"
#include "parser.h"


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
    
}