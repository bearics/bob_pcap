#include <QCoreApplication>
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */

    /* ether, ip, tcp header*/
    struct ether_header *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;


    int res;
    const u_char *pkt;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    char buf[INET_ADDRSTRLEN];

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("Device is %s\n", "dum0");
    /* Open the session in promiscuous mode */
    handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "dum0", errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while((res = pcap_next_ex( handle, &header, &pkt)) >= 0){

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        printf("================================================\n");
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

        /* Print Ether Mac Address*/
        eth=(struct ether_header*)pkt;
        printf("eth.dmac: %s\n",ether_ntoa(((ether_addr*)eth->ether_dhost)));
        printf("eth.smac: %s\n",ether_ntoa(((ether_addr*)eth->ether_shost)));

        /* Check IPv4 */
        if(ntohs(eth->ether_type) != ETHERTYPE_IP)  continue;
        ip=(struct iphdr*)(pkt+ETH_HLEN);

        /* Print IP Address */
        printf("IP.sip: %s\n",inet_ntop(AF_INET, &(ip->saddr), buf, INET_ADDRSTRLEN));
        printf("IP.dip: %s\n",inet_ntop(AF_INET, &(ip->daddr), buf, INET_ADDRSTRLEN));

        /* Check TCP */
        if(ip->protocol != IPPROTO_TCP)    continue;
        tcp=(struct tcphdr*)(pkt + ETH_HLEN + (int)(*(&(ip->tos)-1))/16*5);

        /* Print TCP Port */
        printf("TCP.sport: %d\n", ntohs(tcp->th_sport));
        printf("TCP.dport: %d\n", ntohs(tcp->th_dport));

        /* Print Data */
        printf("--------------DATA--------------\n");
        for(int i=0; i< (ETH_HLEN + (int)(*(&(ip->tos)-1))/16*5 + (tcp->th_off*4))%16; i++) printf("   ");
        for(int i = ETH_HLEN + (int)(*(&(ip->tos)-1))/16*5 + (tcp->th_off*4); i < header->len ; i++)
        {
            printf("%02x ",*(pkt+i));
            if((i+1)%16==0 && i!=0)printf("\n");
        }
        printf("\n");
    }
    return(0);
}
