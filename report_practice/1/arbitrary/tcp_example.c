#include <pcap.h>
#include <netinet/in.h>

#define SIZE_ETHERNET 14

// TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   // source port
    u_short th_dport;   // dest port
    tcp_seq th_seq;     // sequence num
    tcp_seq th_ack;     // ack num
    u_char th_offx2;    // data offset, rsvd
#define TH_OFF(th)  (((th)->th_offx2 &0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     // window
    u_short th_sum;     // checksum
    u_short th_urp;     // urgent pointer
};

struct sniff_ip
{
    u_char ip_vhl;          // version << 4 | header length >> 2
    u_char ip_tos;          // type of service
    u_short ip_len;         // total length
    u_short ip_id;          // identification
    u_short ip_off;         // fragment offset field
#define IP_RF 0X8000        // reserved fragment flag
#define IP_dF 0x4000        // dont fragment flag
#define IP_MF 0x2000        // more fragments flag
#define IP_OFFMASK 0x1fff   // mask for fragmenting bits
    u_char ip_ttl;          // time to live
    u_char ip_p;            // protocol
    u_short ip_sum;         // checksum

    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)


int main(int argc, char *argv[])
{
    char *dev = argv[1], errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "port 80";

    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    const struct sniff_ip *ip;      // The IP header
    const struct sniff_tcp *tcp;    // The TCP header
    const char *payload;

    u_int size_ip;
    u_int size_tcp;
    
    /*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    */
    printf("Device: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 123, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    packet = pcap_next(handle, &header);
    printf("Jacked a packet with length of [%d]\n", header.len);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;

    if(size_ip < 20)
    {
        printf("    *Invalid IP header length: %u bytes\n", size_ip);
        return 0;
    }

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    if(size_tcp < 20){
        printf("    * Invalid TCP header length: %u bytes\n", size_tcp);
        return 0;
    }

    printf("Src Port 0x%x\n", tcp->th_sport);
    printf("Dst Port 0x%x\n", tcp->th_dport);
    printf("Protocol %d\n", ip->ip_p);

    pcap_close(handle);

    return 0;
}