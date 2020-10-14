#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

struct ether_header *eth;
struct ip *iph;
struct tcphdr *tcph;

#define ETHERNET_SIZE 14
// ether_addr_len = 6
// ip_header_len = 4
// ip_version = 4
// ip_frag_offset = 5;


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void etherHandle(const u_char *packet)
{
  eth = (struct ether_header *)packet;
  u_short ether_type = ntohs(eth->ether_type);

  // print out ether header 
  printf("\n=========ETHERNET HEADER==========\n");
  printf("Dst Mac Addr : ");
  for(int i=0; i<ETHER_ADDR_LEN; i++)
    printf("%d",eth->ether_dhost[i]);
  printf("\n");
  
  // src mac
  printf("Src Mac Addr : ");
  for(int i=0; i<ETHER_ADDR_LEN; i++)
    printf("%d", eth->ether_shost[i]);

}

void tcpHandle(const unsigned char *packet, int ip_size)
{
  tcph = (struct tcphdr *)(packet + ETHERNET_SIZE + ip_size);
  printf("\n============TCP HEADER==========\n");
  printf("Src Port : %d\n", ntohs(tcph->th_sport));
  printf("Dst Port : %d\n", ntohs(tcph->th_dport)); 

  packet += (tcph -> th_off);
  printf("\n=========Payload Data==========\n");
  for(int i = 0; i < 14; i++){
          printf("%02x",*(packet++));
          if(i % 14 == 0 && i != 0)
                  printf("\n");
  }
}

void ipHandle(const unsigned char *packet)
{
  iph = (struct ip *)(packet + sizeof(struct ether_header));

  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
  printf("\n=========IP HEADER==========\n");

  
  printf("Src IP : %s \n", src_ip);
  printf("Dst IP : %s \n", dst_ip);  
  // printf("\n");

  if(iph->ip_p == IPPROTO_TCP)
  {
    int ip_size = iph->ip_hl*4;
    tcpHandle(packet, ip_size);
  }

}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  putchar('\n');  //eth0 maybe

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    // printf("%u bytes captured\n", header->caplen);

    etherHandle(packet);
    ipHandle(packet);
  }

  pcap_close(handle);
  return 0;
}
