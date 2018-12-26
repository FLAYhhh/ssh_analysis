/***************************
 * file: main.c
 *
 * Description:
 * print some information in a ssh connection
 *
 * Compile with:
 * gcc -Wall -pedantic pcap_main.c -lpcap (-o foo_err_something)
 *
 * Usage:
 * a.out (# of packets) "filter string"
 * ***********************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include "ssh_analysis.h"
/*
 * workhorse function, we will be modifying this funciton
 * 
 */
void *handle = NULL;

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *eptr;
    eptr = (struct ether_header *) packet;

    fprintf(stdout, "ethernet header source: %s"
            , ether_ntoa(eptr->ether_shost));
    fprintf(stdout, "destination: %s "
            , ether_ntoa(eptr->ether_dhost));
    if(ntohs(eptr->ether_type) == ETHERTYPE_IP)
    {
        fprintf(stdout, "(IP)");
    }else if(ntohs(eptr->ether_type)==ETHERTYPE_ARP)
    {
        fprintf(stdout, "(ARP)");
    }else if(ntohs(eptr->ether_type)==ETHERTYPE_REVARP)
    {
        fprintf(stdout, "(RARP)");
    }else{
        fprintf(stdout, "(?)");
        exit(1);
    }
    fprintf(stdout, "\n");
    return eptr->ether_type;
}

struct my_ip{
    u_int8_t    ip_vhl;
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;
    u_int16_t   ip_len;
    u_int16_t   ip_id;
    u_int16_t   ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK  0x1fff
    u_int8_t    ip_ttl;
    u_int8_t    ip_p;
    u_int16_t   ip_sum;
    struct  in_addr  ip_src, ip_dst;
};

struct my_tcp{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
#define TH_OFF(tcp)  (((tcp)->data_offset & 0xf0) >> 4 )
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_p;
};


u_int8_t handle_IP
(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;

    int len;
    int trans_p;

    /*jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);
    
    if(length < sizeof(struct my_ip))
    {
        printf("tructated ip %d", length);
        return 0;
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);
    trans_p = ip->ip_p;

    if(version != 4)
    {
        fprintf(stdout, "Unknown version %d\n", version);
        return 0;
    }

    if(hlen<5)
    {
        fprintf(stdout, "bad-hlen %d \n", hlen);
    }

    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n", len-length);

    off = ntohs(ip->ip_off);
    {
        fprintf(stdout, "IP: ");
        fprintf(stdout,"%s -> ", inet_ntoa(ip->ip_src));
        fprintf(stdout,"%s hlen:%d version:%d len:%d off:%d\n", inet_ntoa(ip->ip_dst),hlen,version,len,off);
#define TCP_NUM 6
        if(trans_p == TCP_NUM){
            //fprintf(stdout, "TCP protocol\n");
            return TCP_NUM;
        }
    }
    return 0;
}

void handle_TCP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    const struct my_ip *ip;
    const struct my_tcp *tcp;
    u_int ip_hlen;
    u_int ip_len;
    u_int tcp_len;
    
    /*jump pass the ethrnet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    ip_hlen = IP_HL(ip)*4; 
    ip_len = ntohs(ip->ip_len);
    
    // jump pass the ip header
    tcp = (struct my_tcp*)((u_char*)ip + ip_hlen);
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);
    u_int  data_offset = TH_OFF(tcp)*4;
    printf("ip_len:%d, ip_hlen:%d, data_offset:%d\n",ip_len, ip_hlen, data_offset);
    tcp_len = ip_len - ip_hlen - data_offset;
    
    // handle ssh
    if(src_port == 22 || dst_port == 22){
        int direction;
        if(src_port == 22) direction = 1;  // s -> c
        if(dst_port == 22) direction = 0;  // c -> s
        puts("handle ssh");
        //static void *handle = NULL;
        //printf("handle addr(before init):%x\n", handle);
        //static ssh_cnt = 0;
        //ssh_cnt ++;
        //if(ssh_cnt == 1){
        //    printf("init\n");
        //    proto_ssh_init(&handle, NULL);
        //    printf("handle addr(after init):%x\n", handle);
        //}
        printf("TCP len: %d\n", tcp_len);
        printf("handle addr(when passed in):%x\n", handle);
        process_ssh_stream(handle, ((char*)tcp)+ data_offset, tcp_len, direction);
    }
}

void my_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_int16_t type = ntohs(handle_ethernet(args, pkthdr, packet));
    puts("finish handle ether");
    //printf("type:%d   eher_ip:%d",(int)type,(int)ETHERTYPE_IP);
    if(type == ETHERTYPE_IP)
    {
        puts("handle ip");
        u_int8_t trans_type = handle_IP(args, pkthdr, packet);
        if(trans_type == TCP_NUM){
            puts("handle tcp");
            handle_TCP(args, pkthdr, packet);
        }
    }else if(type == ETHERTYPE_ARP)
    {
    }
    else if(type == ETHERTYPE_REVARP)
    {
    }  
    puts("------------------------------------");
}

int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program  fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    u_char *args = NULL;

    /* Options must b passed in as a string */
    if(argc < 2 ){
        fprintf(stdout, "Usage: %s numpackets \"options\"\n", argv[0]);
        return 0;
    }

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n", errbuf); exit(1);}

    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n", errbuf); exit(1);}

    if(argc >3)
    {
        /* Lets try and compile the programe.. non-optimized */
        if(pcap_compile(descr, &fp, argv[2], 0, netp) == -1)
        { fprintf(stderr, "Error calling pcap_compile\n"); exit(1);}
        if(pcap_setfilter(descr, &fp) == -1)
        { fprintf(stderr, "Error setting filter\n"); exit(1);}

    }
    proto_ssh_init(&handle, NULL);
    pcap_loop(descr, atoi(argv[1]), my_callback, args);

    proto_ssh_release(&handle);
    fprintf(stdout, "\nfinished\n");
    return 0;
}


