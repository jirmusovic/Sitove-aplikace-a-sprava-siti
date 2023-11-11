/**
 * @file        argcheck.cpp
 * @author      Veronika Jirmusová (xjirmu00@vutbr.cz)
 * @brief       Implementation of the ArgCheck class for parsing command line arguments.
 *
 *              This source file contains the implementation of the ArgCheck class, which is
 *              responsible for parsing command line arguments related to DHCP statistics. The
 *              class defines methods to extract options such as input from a file (`-r`), interface
 *              name (`-i`), and IP prefixes. Additionally, it includes a method for checking the
 *              correctness of IP prefixes using regular expressions.
 *
 *              The ArgCheck class serves as a utility for initializing program parameters based
 *              on command line inputs. It is part of a larger DHCP statistics program that analyzes
 *              DHCP traffic and provides statistical information. The implementation utilizes the
 *              getopt function for parsing command line options and the regex library for IP prefix
 *              validation.
 *
 * @version     0.1
 * @date        10-11-2023
 * 
 * @copyright   Copyright (c) 2023
 * 
 */

#include "argcheck.h"

// Default constructor definition
ArgCheck::ArgCheck() = default;

// Parameterized constructor definition for parsing command line arguments
ArgCheck::ArgCheck(int argc, char* argv[]){
    int opt;
    is_pcap = false;
    is_interface = false;
    pcap_file = nullptr;
    interface = nullptr;

    // Parse command line arguments using getopt
    while ((opt = getopt(argc, argv, "hr:i:")) != -1) {
        switch (opt) {
        // Print usage information and exit if -h is specified
        case 'h':
            std::cout << "Hello there!\nsThe correct way to start the program is here: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]" << std::endl;
            exit(1);
            break;
        // Set file that needs to be used and indicate that -r is specified
        case 'r':
            pcap_file = optarg;
            is_pcap = true;
            break;
        // Set interface and indicate that -i is specified
        case 'i':
            interface = optarg;
            is_interface = true;
            break;
        }
    }

    // Check if both -r and -i are specified, and exit if so
    if (is_pcap && is_interface) {
        std::cout << "Specify either -r or -i, not both." << std::endl;
        exit(-1);
    }

    // Point to the remaining command line arguments
    pref= &argv[optind];
    pref_cnt = argc - optind;

    // Validate each IP prefix using the isCorrect function
    for(int i = 0; i < pref_cnt; i++){
        if(!isCorrect(pref[i])){
            std::cout << "Incorrect form of ip-prefix " << pref[i] << std::endl;
            exit(-2);
        }
    }

}

// Using regex, check given IP
bool ArgCheck::isCorrect(const std::string& vstup){
    std::regex regexIP("^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\\/([0-9]|[1-2][0-9]|3[0-2])$");
    return std::regex_match(vstup, regexIP);
}       