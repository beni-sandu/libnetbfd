#include <libnet.h>
#include <stdlib.h>
#include <stdio.h>
#include "bfd_session.h"
#include "bfd_packet.h"

int main(int argc, char **arv) {

    libnet_t *l;                                /* libnet context */
    char errbuf[LIBNET_ERRBUF_SIZE];            /* libnet error buffer */
    char *src_ip_c = "192.168.1.1";
    char *dst_ip_c = "192.168.1.2";
    uint32_t src_ip;
    uint32_t dst_ip;
    int src_port = BFD_SRC_PORT_MIN;
    int dst_port = BFD_CTRL_PORT;
    struct bfd_ctrl_packet pkt;                 /* BFD packet */
    libnet_ptag_t udp_tag = 0, ip_tag = 0;      /* libnet tags */
    struct libnet_stats ls;                     /* libnet stats */
    int c;

    l = libnet_init(
            LIBNET_RAW4,                /* injection type */
            NULL,                       /* network interface */
            errbuf);                    /* error buffer */

    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if ((src_ip = libnet_name2addr4(l, src_ip_c, LIBNET_DONT_RESOLVE)) == -1) {
        fprintf(stderr, "Bad source IP address: %s\n", src_ip_c);
        exit(EXIT_FAILURE);
    }

    if ((dst_ip = libnet_name2addr4(l, dst_ip_c, LIBNET_DONT_RESOLVE)) == -1) {
        fprintf(stderr, "Bad destination IP address: %s\n", dst_ip_c);
        exit(EXIT_FAILURE);
    }

    /* Build BFD packet */
    /* Hardcoded values for test:
        Diag code               = 0
        Session state           = 1
        Detection multiplier    = 1
        My discriminator        = 0xbadc0ffe
        Your discriminator      = 0
        Req min TX interval     = 1000000 (in usec)
        Req min TX interval     = 1000000 (in usec)
    */
    bfd_build_packet(0, 1, 1, 0xbadc0ffe, 0, 100000, 100000, &pkt);

    uint8_t payload_size = sizeof(pkt);
    uint8_t *payload = (uint8_t *)&pkt;

    /* Build UDP header */
    udp_tag = libnet_build_udp(
        src_port,                                       /* Source port */
        dst_port,                                       /* Destination port */
        LIBNET_UDP_H + payload_size,                    /* Packet lenght */
        0,                                              /* Checksum */
        payload,                                        /* Payload */
        payload_size,                                   /* Payload size */
        l,                                              /* libnet handle */
        udp_tag);                                       /* libnet tag */

    if (udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return EXIT_FAILURE;
    }

    /* Build IP header */
    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + payload_size + LIBNET_UDP_H,    /* Packet length */
        0,                                              /* TOS */
        0,                                              /* IP ID */
        0,                                              /* IP fragmentation */
        64,                                             /* TTL */
        IPPROTO_UDP,                                    /* Upper layer protocol */
        0,                                              /* Checksum */
        src_ip,                                         /* Source IP address */
        dst_ip,                                         /* Destination IP address */
        NULL,                                           /* Payload (filled at upper layer) */
        0,                                              /* Payload size */
        l,                                              /* libnet handle */
        ip_tag);                                        /* libnet tag */
    
    if (ip_tag == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return EXIT_FAILURE;
    }
    
    /* Send 3 identical BFD packets on wire */
    for (int i = 0; i < 3; i++) {
        
        fprintf(stdout, "Trying to send %d bytes packet\n", libnet_getpacket_size(l));
        c = libnet_write(l);

        if (c == -1) {
            fprintf(stderr, "Write error %s\n", libnet_geterror(l));
            libnet_destroy(l);
            return EXIT_FAILURE;
        } else {
            fprintf(stdout, "Wrote UDP packet on wire, size %d\n", c);
        }
    }

    /* Print stats */
    libnet_stats(l, &ls);
    fprintf(stdout, "Packets sent:          %ld\n"
                    "Packet errors:         %ld\n"
                    "Total bytes written:   %ld\n",
                    ls.packets_sent, ls.packet_errors, ls.bytes_written);


    libnet_destroy(l);
    
    return EXIT_SUCCESS;
}