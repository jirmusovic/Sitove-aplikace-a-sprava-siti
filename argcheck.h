/**
 * @file        argcheck.h
 * @author      Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief       Heathers for argcheck.cpp
 * @version     0.1
 * @date        10-11-2023
 * 
 * @copyright   Copyright (c) 2023
 * 
 */

#ifndef _ARGCHECK_H_
#define _ARGCHECK_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <regex>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>

/**
 * @brief Class to handle command line arguments and IP prefix validation.
 * 
 */
class ArgCheck{
    private:

    public:
        ArgCheck();                                 // Constructor
        ArgCheck(int argc, char* argv[]);           // Parsing command line arguments
        bool isCorrect(const std::string& vstup);   // Regex checking given IP

        bool is_pcap, is_interface;
        char *interface, *pcap_file;
        char **pref;
        int pref_cnt;
};


#endif
