#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string.h>

#define IP_PROTOCOL_TCP  0x06
#define IP_PROTOCOL_UDP  0x11
#define IP_PROTOCOL_ICMP 0x01

struct ip_address {
    uint8_t octets[4];
};

// Parameters:
// raw_address_netbytes - raw ip_address bytes in the network order
struct ip_address get_ip_addr_from_uint32(const uint32_t raw_address_netbytes);

// Parameters:
// ip_addr - is a pointer to the ip_address struct that must be converted to string
// to_str - is a pointer to the char array, where the string will be put. Must be at least
//          16 chars long
void get_ip_addr_str(const struct ip_address *ip_addr, char *to_str);

// Parameters:
// ip_addr - is a pointer to the ip_address struct that must be converted to string
char *get_ip_addr_str_malloced(const struct ip_address *ip_addr);

// Parameters:
// ip_addr - pointer to the ip_address struct to be printed
void print_ip_addr(struct ip_address *ip_addr);

// Parameters: 
// bytes - pointer to the bytes array, that contains the ethernet frame
void analyze_bytes(const u_char *bytes);

void print_usage();

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        exit(0);
    }

    // capture (.pcap) file name
    const char *filename = argv[1];

    // error buffer, where libpcap will put its error messages
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr *pkthdr;

    pcap_t *handle = pcap_open_offline(filename, errbuf);

    if (handle == NULL) {
        printf("Error: %s\n", errbuf);
        exit(1);
    }

    int next_status = 0;

    do {
        const u_char *bytes;

        next_status = pcap_next_ex(handle, &pkthdr, &bytes);

        analyze_bytes(bytes);
    
    } while (next_status != 0 && next_status != PCAP_ERROR_BREAK); 

    return 0;
}

void print_usage() {
    printf("Usage: traffan <filename>.pcap\n");
}

struct ip_address get_ip_addr_from_uint32(const uint32_t raw_address_netbytes) {
    struct ip_address *ip_addr = (struct ip_address * ) &raw_address_netbytes;

    return *ip_addr; 
}

void print_ip_addr(struct ip_address *ip_addr) {
    printf("IP: %d.%d.%d.%d\n", ip_addr->octets[0],
                                ip_addr->octets[1],
                                ip_addr->octets[2],
                                ip_addr->octets[3]);
}

void get_ip_addr_str(const struct ip_address *ip_addr, char *to_str) {
    sprintf(to_str, 
            "%d.%d.%d.%d", 
            ip_addr->octets[0],
            ip_addr->octets[1],
            ip_addr->octets[2],
            ip_addr->octets[3]
        );
}

char *get_ip_addr_str_malloced(const struct ip_address *ip_addr) {
    char *str = malloc(sizeof(char) * 16);

    sprintf(str, 
            "%d.%d.%d.%d", 
            ip_addr->octets[0],
            ip_addr->octets[1],
            ip_addr->octets[2],
            ip_addr->octets[3]
        );
    return str;
}

void analyze_bytes(const u_char *bytes) {
    const u_char *eth_start = bytes;

    const u_char *ip_start = eth_start + sizeof(struct ethhdr);

    struct ethhdr *eth_header = (struct ethhdr * ) eth_start;

    struct iphdr *ip_header = (struct iphdr * ) ip_start;

    struct ip_address saddr = get_ip_addr_from_uint32(
            ip_header->saddr
        );

    struct ip_address daddr = get_ip_addr_from_uint32(
            ip_header->daddr
        );   

    char *saddr_str = get_ip_addr_str_malloced(&saddr); 
    char *daddr_str = get_ip_addr_str_malloced(&daddr); 

    printf("IP packet, source address: %s, destination address: %s\n", 
            saddr_str, daddr_str
        );

    const u_char *transport_start = ip_start + ip_header->ihl * 4;

    if (ip_header->protocol == IP_PROTOCOL_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr * ) transport_start;

        printf("    TCP header, source port: %d, destination port: %d, "
                "sequence number: %u\n",
                ntohs(tcp_header->th_sport), 
                ntohs(tcp_header->th_dport),
                ntohl(tcp_header->seq)           
            );

    } else if (ip_header->protocol == IP_PROTOCOL_UDP) {
        struct udphdr *udp_header = (struct udphdr * ) transport_start;

        printf("    UDP header, source port: %d, destination port: %d\n",
                ntohs(udp_header->uh_sport), 
                ntohs(udp_header->uh_dport) 
            );           

    } else if (ip_header->protocol == IP_PROTOCOL_ICMP) {
        struct icmphdr *icmp_header = (struct icmphdr * ) transport_start;
        
        printf("    ICMP header, type: %#04x\n", icmp_header->type);
    }

    free(saddr_str);
    free(daddr_str);
}