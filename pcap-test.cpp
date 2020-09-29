#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

struct etherhdr *pk_eth;
struct iphdr *pk_ip;
struct tcphdr *pk_tcp;

#define ETHERNET_SIZE 14
// ether_addr_len = 6
// ip_header_len = 4
// ip_version = 4
// ip_frag_offset = 5;
#define ETH_ALEN 6
#define ETH_HLEN 14
#define IPV4_HL_MIN 20
#define IPV4_ALEN 0x04
#define TCP_PAYLOAD_MAXLEN 16

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

char errbuf[PCAP_ERRBUF_SIZE];

void etherHandle(const u_char *pk)
{
	pk_eth = (struct etherhdr *)pk;
	u_short ether_type = ntohs(pk_eth->ether_type);
	printf("\n=========ETHERNET HEADER==========\n");
	printf("Src Mac Addr : ");
	for (int i = 0; i<ETH_ALEN; i++)
		printf("%s%02X", (i ? ":" : ""), pk_eth->ether_src[i]);

	printf("Dst Mac Addr : ");
	for (int i = 0; i<ETH_ALEN; i++)
		printf("%s%02X", (i ? ":" : ""), pk_eth->ether_dst[i]);
}

void tcpHandle(const unsigned char *pk, int ip_size)
{
	pk_tcp = (struct tcphdr *)(pk + ETHERNET_SIZE + ip_size);
	printf("\n============TCP HEADER==========\n");
	printf("Src Port : %d\n", ntohs(pk_tcp->th_src));
	printf("Dst Port : %d\n", ntohs(pk_tcp->th_dst));

}

void ipHandle(const unsigned char *pk)
{
	pk_ip = (struct iphdr *)(pk + sizeof(struct etherhdr));

	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pk_ip->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(pk_ip->ip_dst), dst_ip, INET_ADDRSTRLEN);
	printf("\n=========IP HEADER==========\n");
	printf("Src IP : ");
	for (int i = 0; i < IP_ALEN; ++i) {
		printf("%s \n", src_ip);
	}
	printf("Dst IP : ");
	for (int i = 0; i < IP_ALEN; ++i) {
		printf("%s\n", dst_ip);
	}

	if (pk_ip->ip_p == IPPROTO_TCP)
	{
		int ip_size = pk_ip->ip_hl * 4;
		tcpHandle(pk, ip_size);
	}

}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	pcap_t* handle = pcap_open_live(argv1[1], BUFSIZ, 1, 1000, errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Can't find default device: %s\n", errbuf);
		return 1;
	}
	if (handle == NULL) {
		fprintf(stderr, "Can't find default device %s: %s\n", dev, errbuf);
		return 1;
	}

	printf(dev);
	putchar('\n');  //eth0

	while (true) {
		struct pcap_pkthdr* hd;
		const u_char* pk;
		int res = pcap_next_ex(handle, &hd, &pk);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("Packet Length: %u\n", hd->caplen);

		etherHandle(pk);
		ipHandle(pk);
	}

	pcap_close(handle);
	return 0;
}