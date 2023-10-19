/*
 * read-pcap.c: read the pcap file given as the first argument and prints Ethernet headers
 *
 * Usage: ./read-pcap <file-name>
 *
 * (c) Petr Matousek, 2020
 * updates: 09/2023 - ethertypes VLAN and LLDP added; ICMPv4, IPv6 next headers
 *          10/2023 - VLAN decapsulation for IPv4, IPv6 and ARP
 *
 * notes: expects Ethernet II encapsulation, does not recognize 802.3 standard or virtual frames
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <err.h>

#ifdef __linux__            // for Linux
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#define ETHERTYPE_LLDP 0x88cc
struct ether_vlan_header {
        uint8_t evl_dhost[ETHER_ADDR_LEN];
        uint8_t evl_shost[ETHER_ADDR_LEN];
        uint16_t evl_encap_proto;
        uint16_t evl_tag;
        uint16_t evl_proto;
} __packed;
#endif

struct pcap_pkthdr header; 

#ifdef __APPLE__           // for MacOS
struct ether_vlan_header {
        uint8_t evl_dhost[ETHER_ADDR_LEN];
        uint8_t evl_shost[ETHER_ADDR_LEN];
        uint16_t evl_encap_proto;
        uint16_t evl_tag;
        uint16_t evl_proto;
} __packed;
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define ETHERNET_HEADER (14)     // offset of Ethernet header
#define IPV6_HEADER (40)         // length of IPv6 header
#define VLAN_HEADER (4)          // length of IEEE 802.1q header



/*
 *  analyze_udp() - receives a pointer to the UDP header; extracts, and prints selected UDP headers
 * 
 */
void analyze_udp(const u_char *packet, u_int len){ // see /usr/include/netinet/udp.h
  const struct udphdr *my_udp;

  my_udp = (const struct udphdr*) packet;
  printf("\tSrc port = %d, dst port = %d, UDP length = %d B\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
  
  #define LINE_LEN 16
  /* Print the packet */
    for (int i= 1 + sizeof(my_udp) ; (i < header.caplen + 1 - ETHERNET_HEADER - len) ; i++)
    {
        printf("%.2x ", packet[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
    
    printf("\n\n"); 

  return;
}

/*
 *  analyze_ip() - receives a pointer to the IPv4 header; extracts, and prints selected IP headers
 * 
 */
void analyze_ip(const u_char *packet){    // see /usr/include/netinet/ip.h
  u_int header_len;                       // IPv4 header length
  struct ip* my_ip;

  my_ip = (struct ip*) (packet);
  header_len = my_ip->ip_hl*4;            // compute IP4 header length
  printf("\tIP: id 0x%x, hlen = %d bytes, version %d, IP length = %d bytes, TTL = %d\n",ntohs(my_ip->ip_id),header_len,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
  printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
  printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));
      
  switch (my_ip->ip_p){                         // see IPPROTO_ definitions in /usr/include/netinet/in.h
  
  
  
  case IPPROTO_UDP:    // UDP protocol = 17
    printf(", protocol = %d (UDP)\n",my_ip->ip_p);
    analyze_udp(packet + header_len, header_len);           // move the pointer to the beginning of UDP header
    break;
  default: 
    printf(", protocol %d\n",my_ip->ip_p);
  }
  return;
}

/*
 * main function
 *
 */ 
int main(int argc, char *argv[]){
  int n;
  char errbuf[PCAP_ERRBUF_SIZE];  // constants defined in pcap.h
  const u_char *packet;               // pointer to the captured packet
           // PCAP header (packet envelope created by a packet capturing tool)
  struct ether_header *eptr;          // Ethernet header
  struct ether_vlan_header *my_vlan;  // 802.1q VLAN header - see /usr/include/net/ethernet.h
  pcap_t *handle;                     // file handle

  if (argc != 2)                      // one parameter expected => input file name 
    errx(1,"Usage: %s <filename>",argv[0]);
  
  // open the input file
    if ((handle = pcap_open_offline(argv[1],errbuf)) == NULL)
    err(1,"Can't open file %s for reading",argv[1]);
  
  printf("Opening file %s for reading ...\n\n", argv[1]);
  n = 0;
  
  // read packets from the file
  while ((packet = pcap_next(handle,&header)) != NULL){
    n++;
    // print the captured packet info: packet number, length and timestamp
    printf("Packet no. %d:\n",n);
    printf("\tPacket length = %d bytes, received at %s",header.len,ctime((const time_t*)&header.ts.tv_sec));  
    
    // read the Ethernet header
    eptr = (struct ether_header *) packet;
    printf("\tSource MAC = %s, ",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
    printf("Destination MAC = %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;
    
    switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
    case ETHERTYPE_IP:    // IPv4 = 0x0800
      printf("\tEthernet type = 0x%04x (IPv4 packet)\n", ntohs(eptr->ether_type));
      analyze_ip(packet+ETHERNET_HEADER);           // skip the Ethernet header
      break;
    case ETHERTYPE_IPV6:  // IPv6 = 0x86DD
      printf("\tEthernet type = 0x%04x (IPv6 packet)\n",ntohs(eptr->ether_type));
      // analyze_ip6(packet+ETHERNET_HEADER);          // skip the Ethernet header
      break; 
    case ETHERTYPE_ARP:  // ARP = 0x0806
      printf("\tEthernet type  = 0x%04x (ARP packet)\n",ntohs(eptr->ether_type));
      break;
    case ETHERTYPE_VLAN: // VLAN 802.1q = 0x8100
      my_vlan = (struct ether_vlan_header *) packet;
      printf("\tEthernet type = 0x%04x (VLAN encapsulation), VLAN ID = %d, Protocol = 0x%04x\n",ntohs(eptr->ether_type),ntohs(my_vlan->evl_tag), ntohs(my_vlan->evl_proto));
      switch (ntohs(my_vlan->evl_proto)){           // analyze encapsulated protocols following VLAN tag
      case ETHERTYPE_IP:
	printf("\tEthernet type = 0x%04x (IPv4 packet)\n", ntohs(my_vlan->evl_proto));
	// analyze_ip(packet+ETHERNET_HEADER+VLAN_HEADER);      // skip Ethernet and 802.1q headers
	break;
      case ETHERTYPE_IPV6:
	printf("\tEthernet type = 0x%04x (IPv4 packet)\n", ntohs(my_vlan->evl_proto));
	// analyze_ip6(packet+ETHERNET_HEADER+VLAN_HEADER);     // skip Ethernet and 802.1q headers
	break;
      case ETHERTYPE_ARP:
	printf("\tEthernet type = 0x%04x (ARP packet)\n",ntohs(my_vlan->evl_proto));
	break;
      default:
	printf("\tEthernet type = 0x%04x\n",ntohs(my_vlan->evl_proto));
	break;
	}
      break;
    case ETHERTYPE_LLDP: // Link Layer Discovery Protocol
      printf("\tEthernet type = 0x%04x (LLDP frame)\n",ntohs(eptr->ether_type));
      break;
    default:             // other L2 protocols
      printf("\tEthernet type = 0x%04x (not an IP packet)\n", ntohs(eptr->ether_type));
    } 
  }
  printf("End of file reached ...\n");
  
  // close the capture device/file and deallocate resources
  pcap_close(handle);
  return 0;
}