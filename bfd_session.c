#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include "bfd_packet.h"
#include "libbfd.h"

/* Entry point of a new BFD session */
void *bfd_session_run(void *args) {

    libnet_t *l;                                /* libnet context */
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];     /* libnet error buffer */
    pcap_t *pcap_handle;                        /* pcap handle */
    char pcap_errbuf[PCAP_ERRBUF_SIZE];         /* pcap error buffer */
    uint32_t src_ip;                            /* Local IP in binary form */
    uint32_t dst_ip;                            /* Remote IP in binary form */
    char if_name[32];                           /* Local interface used on capturing */
    struct bfd_ctrl_packet pkt;                 /* BFD control packet */
    libnet_ptag_t udp_tag = 0, ip_tag = 0;      /* libnet tags */
    struct libnet_stats ls;                     /* libnet stats */
    int c;

    /* Useful pointers */
    struct bfd_session_params *curr_params = (struct bfd_session_params *)args;
    struct bfd_session new_session;
    curr_params->current_session = &new_session;
    struct bfd_session *curr_session = curr_params->current_session;

    /* Init packet injection library */
    l = libnet_init(
            LIBNET_RAW4,                        /* injection type */
            NULL,                               /* network interface */
            libnet_errbuf);                     /* error buffer */

    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    if ((src_ip = libnet_name2addr4(l, curr_params->src_ip, LIBNET_DONT_RESOLVE)) == -1) {
        fprintf(stderr, "Bad source IP address: %s\n", curr_params->src_ip);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    if ((dst_ip = libnet_name2addr4(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE)) == -1) {
        fprintf(stderr, "Bad destination IP address: %s\n", curr_params->dst_ip);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* We have valid IP addresses, so let's search for an interface */
    /* TODO: should this also check if the link is UP or just if IP is assigned? */
    if (search_device_by_ip(curr_params->src_ip, false, if_name) == -1) {
        fprintf(stderr, "No interface was found with IP: %s\n", curr_params->src_ip);
        exit(EXIT_FAILURE);
    }

    pr_debug("Found device: %s, for IP: %s\n", if_name, curr_params->src_ip);

    /* Seed random generator needed for local discriminator */
    srandom((uint64_t)curr_params);

    /* Configure initial values for the new BFD session */
    curr_session->des_min_tx_interval = curr_params->des_min_tx_interval;
    curr_session->local_diag = BFD_DIAG_NODIAG;
    curr_session->local_discr = (uint32_t)(random());
    curr_session->local_state = BFD_STATE_DOWN;
    curr_session->remote_discr = 0;
    curr_session->remote_min_tx_interval = 0;
    curr_session->remote_state = BFD_STATE_DOWN;
    curr_session->req_min_rx_interval = curr_params->req_min_rx_interval;

    /* Build initial BFD control packet */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, false, false, curr_params->detect_mult,
                curr_session->local_discr, curr_session->remote_discr, curr_params->des_min_tx_interval,
                curr_session->req_min_rx_interval, &pkt);

    /* Build UDP header */
    udp_tag = libnet_build_udp(
        BFD_SRC_PORT_MIN,                                   /* Source port, TODO: needs to be unique for every session */
        BFD_CTRL_PORT,                                      /* Destination port */
        LIBNET_UDP_H + BFD_PKG_MIN_SIZE,                    /* Packet lenght */
        0,                                                  /* Checksum */
        (uint8_t *)&pkt,                                    /* Payload */
        BFD_PKG_MIN_SIZE,                                   /* Payload size */
        l,                                                  /* libnet handle */
        udp_tag);                                           /* libnet tag */

    if (udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Build IP header */
    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + BFD_PKG_MIN_SIZE + LIBNET_UDP_H,    /* Packet length */
        0,                                                  /* TOS */
        0,                                                  /* IP ID */
        0,                                                  /* IP fragmentation */
        64,                                                 /* TTL */
        IPPROTO_UDP,                                        /* Upper layer protocol */
        0,                                                  /* Checksum */
        src_ip,                                             /* Source IP address */
        dst_ip,                                             /* Destination IP address */
        NULL,                                               /* Payload (filled at upper layer) */
        0,                                                  /* Payload size */
        l,                                                  /* libnet handle */
        ip_tag);                                            /* libnet tag */
    
    if (ip_tag == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Send 3 identical BFD packets on wire */
    for (int i = 0; i < 3; i++) {
        
        fprintf(stdout, "Trying to send %d bytes packet\n", libnet_getpacket_size(l));
        c = libnet_write(l);

        if (c == -1) {
            fprintf(stderr, "Write error %s\n", libnet_geterror(l));
            libnet_destroy(l);
            exit(EXIT_FAILURE);
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

    return NULL;
}

/* 
 * Create a new BFD session, returns a session id
 * on successful creation, -1 otherwise
 */
bfd_session_id bfd_session_start(struct bfd_session_params *params) {
    
    pthread_t session_id;
    int ret;

    ret = pthread_create(&session_id, NULL, bfd_session_run, (void *)params);

    if (ret) {
        fprintf(stderr, "bfd_session_create failed, err: %d\n", ret);
        return -1;
    }

    return session_id;
}

/* Stop a BFD session */
void bfd_session_stop(bfd_session_id session_id) {

    if (session_id != -1) {
        pr_debug("Stopping BFD session: %ld\n", session_id);
        pthread_cancel(session_id);
    }
}