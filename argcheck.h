#ifndef _ARGCHECK_H_
#define _ARGCHECK_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>

class ArgCheck{
    private:

    public:
        ArgCheck();
        ArgCheck(int argc, char* argv[]);

        bool is_pcap, is_interface;
        char *interface, *pcap_file;
        char **pref;
        int pref_cnt;
};


#endif
