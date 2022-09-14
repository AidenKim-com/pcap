#include <pcap.h>

#define ETHR_ADDR_LEN 6
#define SIZE_ETHERNET 14

struct sniff_ethernet{
    u_char ether_dhost[ETHR_ADDR_LEN]; /* Dest Addr */
    u_char ether_shost[ETHR_ADDR_LEN]; /* Src Addr */
    u_short ether_type;
};

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

    const struct sniff_ethernet *ethernet; // Ethernet Header
    /*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    */
    printf("Device: %s\n", dev);

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 123, 1000, errbuf);
    if(handle==NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    packet = pcap_next(handle, &header);
    printf("Jacked a packet with length of [%d]\n", header.len);

    printf("Pasrsing Ethernet header\n");
    
    ethernet = (struct sniff_ehternet*)(packet);
    printf("Ether Ether Type %d\n", ethernet->ether_type);

    printf("Src Host ");
    for(int i=0;i<5;i++){
        printf("%X:", ethernet->ether_dhost[i]);
    }
    printf("%X\n", ethernet->ether_dhost[5]);

    printf("Dst Host ");
    for(int i=0;i<5;i++){
        printf("%X:", ethernet->ether_shost[i]);
    }
    printf("%x\n", ethernet->ether_shost[5]);


    pcap_close(handle);

    return 0;
}