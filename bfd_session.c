#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/capability.h>

#include "bfd_packet.h"
#include "bfd_session.h"
#include "libbfd.h"

/* Forward declarations */
void tx_timeout_handler(union sigval sv);

int recvfrom_ppoll(int sockfd, char *recv_buf, int buf_size, int timeout_us) {

    struct pollfd fds[1];
    struct timespec ts;
    int ret;

    fds[0].fd = sockfd;
    fds[0].events = POLLIN;

    ts.tv_sec = timeout_us / 1000000;
    ts.tv_nsec = timeout_us % 1000000 * 1000;

    ret = ppoll(fds, 1, &ts, NULL);

    if (ret == -1) {
        perror("ppoll"); //error in ppoll call
    }
    else if (ret == 0) {
        return -2; //timeout expired
    }
    else
        if (fds[0].revents & POLLIN)
            return recvfrom(sockfd, recv_buf, buf_size, 0, NULL, NULL);
    
    return EXIT_FAILURE;
}

/* Entry point of a new BFD session */
void *bfd_session_run(void *args) {

    libnet_t *l;                                        /* libnet context */
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];             /* libnet error buffer */
    uint32_t src_ipv4;                                  /* Local IPv4 in binary form */
    uint32_t dst_ipv4;                                  /* Remote IPv4 in binary form */
    struct libnet_in6_addr dst_ipv6;                    /* Remote IPv6 in binary form */
    struct libnet_in6_addr src_ipv6;                    /* Local IPv6 in binary form */
    //char if_name[32];                                 /* Local interface used on capturing */
    struct bfd_ctrl_packet pkt;                         /* BFD control packet that we send */
    libnet_ptag_t udp_tag = 0, ip_tag = 0;              /* libnet tags */
    int sockfd;                                         /* UDP socket file descriptor */
    struct sockaddr_in sav4;                            /* IPv4 socket address */
    struct sockaddr_in6 sav6;                           /* IPv6 socket address */
    char recv_buf[BFD_PKG_MIN_SIZE];                    /* Buffer for received packet */
    int ret;                                            /* Number of received bytes on socket */
    struct bfd_ctrl_packet *bfdp;                       /* Pointer to BFD packet received from remote peer */
    cap_t caps;
    cap_flag_value_t cap_val;
    //uint32_t tx_jitter = 0;
    //uint32_t jitt_maxpercent = 0;

    struct bfd_timer tx_timer;
    struct sigevent tx_sev;
    struct itimerspec tx_ts;
    //struct itimerspec tx_remain;
    //int c;

    /* Useful pointers */
    struct bfd_session_params *curr_params = (struct bfd_session_params *)args;
    struct bfd_session new_session;
    curr_params->current_session = &new_session;
    struct bfd_session *curr_session = curr_params->current_session;

    /* Check for CAP_NET_RAW capability */
    caps = cap_get_proc();
    if (caps == NULL) {
        perror("cap_get_proc");
        exit(EXIT_FAILURE);
    }

    if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_val) == -1) {
        perror("cap_get_flag");
        exit(EXIT_FAILURE);
    }

    if (cap_val != CAP_SET) {
        fprintf(stderr, "Execution requires CAP_NET_RAW capability.\n");
        exit(EXIT_FAILURE);
    }

    cap_free(caps);

    /* libnet init */
    if (curr_params->is_ipv6 == true) {
        l = libnet_init(
            LIBNET_RAW6,                                /* injection type */
            NULL,                                       /* network interface */
            libnet_errbuf);                             /* error buffer */

        if (l == NULL) {
            fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }

        src_ipv6 = libnet_name2addr6(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);
        if (strncmp((char *)&src_ipv6, (char *)&in6addr_error, sizeof(in6addr_error)) == 0) {
            fprintf(stderr, "Bad source IPv6 address: %s\n", curr_params->src_ip);
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }

        dst_ipv6 = libnet_name2addr6(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE);
        if (strncmp((char *)&dst_ipv6, (char *)&in6addr_error, sizeof(in6addr_error)) == 0) {
            fprintf(stderr, "Bad destination IPv6 address: %s\n", curr_params->dst_ip);
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }
    }
    else {
        l = libnet_init(
            LIBNET_RAW4,                                /* injection type */
            NULL,                                       /* network interface */
            libnet_errbuf);                             /* error buffer */

        if (l == NULL) {
            fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }

        if ((src_ipv4 = libnet_name2addr4(l, curr_params->src_ip, LIBNET_DONT_RESOLVE)) == -1) {
            fprintf(stderr, "Bad source IPv4 address: %s\n", curr_params->src_ip);
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }

        if ((dst_ipv4 = libnet_name2addr4(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE)) == -1) {
            fprintf(stderr, "Bad destination IPv4 address: %s\n", curr_params->dst_ip);
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }
    }

    /* Initialize timer data */
    tx_timer.sess_params = curr_params;
    tx_timer.pkt = &pkt;
    tx_timer.udp_tag = &udp_tag;
    tx_timer.l = l;
    tx_timer.tx_ts = &tx_ts;

    /* Seed random generator used for local discriminator */
    srandom((uint64_t)curr_params);

    /* Configure initial values for the new BFD session */
    //curr_session->des_min_tx_interval = (curr_params->des_min_tx_interval < 1000000) ? 1000000 : curr_params->des_min_tx_interval;
    curr_session->des_min_tx_interval = 1000000;
    curr_session->local_diag = BFD_DIAG_NODIAG;
    curr_session->local_discr = (uint32_t)(random());
    curr_session->local_state = BFD_STATE_DOWN;
    curr_session->remote_discr = 0;
    curr_session->remote_min_rx_interval = 0;
    curr_session->remote_state = BFD_STATE_DOWN;
    curr_session->req_min_rx_interval = curr_params->req_min_rx_interval;
    curr_session->detection_time = 1000000;
    curr_session->local_poll = false;
    curr_session->local_final = false;

    /* Build initial BFD control packet */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
                curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
                curr_session->req_min_rx_interval, &pkt);
    
    /* Get a unique source port for every session */
    src_port++;

    /* Build UDP header */
    udp_tag = libnet_build_udp(
        src_port,                                               /* Source port */
        BFD_CTRL_PORT,                                          /* Destination port */
        LIBNET_UDP_H + BFD_PKG_MIN_SIZE,                        /* Packet lenght */
        0,                                                      /* Checksum */
        (uint8_t *)&pkt,                                        /* Payload */
        BFD_PKG_MIN_SIZE,                                       /* Payload size */
        l,                                                      /* libnet handle */
        udp_tag);                                               /* libnet tag */

    if (udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* Build IP header */
    if (curr_params->is_ipv6 == true) {
        ip_tag = libnet_build_ipv6(
            0,                                                  /* Traffic class(DSCP + ECN) */
            0,                                                  /* Flow label */
            BFD_PKG_MIN_SIZE + LIBNET_UDP_H,                    /* Packet length */
            IPPROTO_UDP,                                        /* Next header(type of first extension layer or protocol in upper layer) */
            255,                                                /* Hop limit(kind of like TTL) */
            src_ipv6,                                           /* Source IP address */
            dst_ipv6,                                           /* Destination IP address */
            NULL,                                               /* Payload (filled at upper layer) */
            0,                                                  /* Payload size */
            l,                                                  /* libnet handle */
            ip_tag);                                            /* libnet tag */
        
        if (ip_tag == -1) {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }
    }
    else {
        ip_tag = libnet_build_ipv4(
            LIBNET_IPV4_H + BFD_PKG_MIN_SIZE + LIBNET_UDP_H,    /* Packet length */
            0,                                                  /* TOS */
            0,                                                  /* IP ID */
            0,                                                  /* IP fragmentation */
            255,                                                /* TTL */
            IPPROTO_UDP,                                        /* Upper layer protocol */
            0,                                                  /* Checksum */
            src_ipv4,                                           /* Source IP address */
            dst_ipv4,                                           /* Destination IP address */
            NULL,                                               /* Payload (filled at upper layer) */
            0,                                                  /* Payload size */
            l,                                                  /* libnet handle */
            ip_tag);                                            /* libnet tag */
    
        if (ip_tag == -1) {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            libnet_destroy(l);
            exit(EXIT_FAILURE);
        }
    }

    /* Initial TX timer configuration, we start sending packets at min 1s as per the standard */
    tx_sev.sigev_notify = SIGEV_THREAD;                        /* Notify via thread */
    tx_sev.sigev_notify_function = &tx_timeout_handler;        /* Handler function */
    tx_sev.sigev_notify_attributes = NULL;                     /* Could be pointer to pthread_attr_t structure */
    tx_sev.sigev_value.sival_ptr = &tx_timer;                  /* Pointer passed to handler */

    /* Configure TX interval */
    tx_ts.it_interval.tv_sec = curr_session->des_min_tx_interval / 1000000;
    tx_ts.it_interval.tv_nsec = curr_session->des_min_tx_interval % 1000000 * 1000;
    tx_ts.it_value.tv_sec = curr_session->des_min_tx_interval / 1000000;
    tx_ts.it_value.tv_nsec = curr_session->des_min_tx_interval % 1000000 * 1000;

    /* Create TX timer */
    if (timer_create(CLOCK_REALTIME, &tx_sev, &tx_timer.timer_id) == -1) {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    /* Create an UDP socket */
    if (curr_params->is_ipv6 == true) {
        if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
    }
    else {
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
    }

    /* Bind the socket */
    if (curr_params->is_ipv6 == true) {
        memset(&sav6, 0, sizeof(struct sockaddr_in));
        sav6.sin6_family = AF_INET6;
        inet_pton(sav6.sin6_family, curr_params->src_ip, &(sav6.sin6_addr));
        sav6.sin6_port = htons(BFD_CTRL_PORT);

        if (bind(sockfd, (struct sockaddr *)&sav6, sizeof(sav6)) == -1) {
            perror("bind");
            exit(EXIT_FAILURE);
        }
    }
    else {
        memset(&sav4, 0, sizeof(struct sockaddr_in));
        sav4.sin_family = AF_INET;
        inet_pton(sav4.sin_family, curr_params->src_ip, &(sav4.sin_addr));
        sav4.sin_port = htons(BFD_CTRL_PORT);
    
        if (bind(sockfd, (struct sockaddr *)&sav4, sizeof(sav4)) == -1) {
            perror("bind");
            exit(EXIT_FAILURE);
        }
    }

    /* Start sending packets */
    bfd_update_timer(curr_session->des_min_tx_interval, &tx_ts, &tx_timer);

    /* Loop for processing incoming packets */
    while (true) {
        
        /* Check our socket for data */
        ret = recvfrom_ppoll(sockfd, recv_buf, BFD_PKG_MIN_SIZE, curr_session->detection_time);

        /* No data available */
        if (ret == -2) {

            /* If we did not get any reponse and session was up, bring it down */
            if (curr_session->local_state == BFD_STATE_UP) {
                curr_session->local_state = BFD_STATE_DOWN;
                curr_session->local_diag = BFD_DIAG_CTRL_DETECT_TIME_EXPIRED;
                pr_debug("Detected BFD remote %s going DOWN.\n", curr_params->dst_ip);
            }
        }

        /* We have some data, get it and process it */
        if (ret > 0) {

            /* Rules for reception of BFD control packets (section 6.8.6 in RFC5880) */
            bfdp = (struct bfd_ctrl_packet *)recv_buf;

            /* If the version number is not correct (1), packet MUST be discarded */
            if (((bfdp->byte1.version >> 5) & 0x07) != 1) {
                pr_debug("Wrong version number.\n");
                continue;
            }
        
            /* If the Length field is not correct, packet MUST be discarded */
            if (bfdp->length != BFD_PKG_MIN_SIZE) {
                pr_debug("Wrong packet length.\n");
                continue;
            }
        
            /* If the Detect Mult field = 0, packet MUST be discarded */
            if (bfdp->detect_mult == 0) {
                pr_debug("Wrong detect mult.\n");
                continue;
            }
        
            /* If the Multipoint bit is != 0, packet MUST be discarded */
            if ((bfdp->byte2.multipoint & 0x01) != 0) {
                pr_debug("Wrong multipoint setting.\n");
                continue;
            }

            /* If My Discr = 0, packet MUST be discarded */
            if (ntohl(bfdp->my_discr) == 0) {
                pr_debug("Bad my_discr value.\n");
                continue;
            }

            /* If Your Discr = zero and State is not Down or AdminDown, packet MUST be discarded */
            if (ntohl(bfdp->your_discr) == 0 && ((((bfdp->byte2.state >> 6) & 0x03) != BFD_STATE_DOWN) ||
                    (((bfdp->byte2.state >> 6) & 0x03) == BFD_STATE_ADMIN_DOWN))) {
                pr_debug("Bad state, zero your_discr.\n");
                continue;
            }

            /* If A bit is set, packet MUST be discarded (we don't support authentication) */
            if (((bfdp->byte2.auth_present >> 2) & 0x01) == true) {
                pr_debug("Authentication is not supported.\n");
                continue;
            }
        
            /* Set BFD session variables */
            curr_session->remote_discr = ntohl(bfdp->my_discr);
            curr_session->remote_state = (bfdp->byte2.state >> 6) & 0x03;
            curr_session->remote_min_rx_interval = ntohl(bfdp->req_min_rx_interval);
            curr_session->remote_version = (bfdp->byte1.version >> 5) & 0x07;
            curr_session->remote_multipoint = bfdp->byte2.multipoint & 0x01;
            curr_session->remote_auth = (bfdp->byte2.auth_present >> 2) & 0x01;
            curr_session->remote_detect_mult = bfdp->detect_mult;
            curr_session->remote_des_min_tx_interval = ntohl(bfdp->des_min_tx_interval);

            /* Update the transmit interval as per section 6.8.2 */
            curr_session->des_min_tx_interval = max(curr_params->des_min_tx_interval, curr_session->remote_min_rx_interval);

            /* Update the Detection Time as per section 6.8.4 */
            curr_session->detection_time = curr_session->remote_detect_mult * curr_session->remote_des_min_tx_interval;

            //pr_debug("<---[%s] Received BFD packet: detect_time = %d, state = %s\n", get_time(t_now), curr_session->detection_time, state2string(curr_session->remote_state));

            /* BFD state machine logic */
            if (curr_session->local_state == BFD_STATE_ADMIN_DOWN) {
                pr_debug("Got BFD packet from: %s while in ADMIN_DOWN.\n", curr_params->dst_ip);
                continue;
            }

            if (curr_session->remote_state == BFD_STATE_ADMIN_DOWN) {
                if (curr_session->local_state != BFD_STATE_DOWN) {
                    curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                    curr_session->local_state = BFD_STATE_DOWN;
                    pr_debug("BFD remote: %s signaled going ADMIN_DOWN.\n", curr_params->dst_ip);
                }
            }
            else {
                if (curr_session->local_state == BFD_STATE_DOWN) {
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                        curr_session->local_state = BFD_STATE_INIT;
                        pr_debug("BFD session: %s going to INIT.\n", curr_params->src_ip);
                    }
                    else if (curr_session->remote_state == BFD_STATE_INIT) {
                        curr_session->local_state = BFD_STATE_UP;
                        pr_debug("BFD session: %s going to UP.\n", curr_params->src_ip);
                    }
                }
                else if (curr_session->local_state == BFD_STATE_INIT) {
                        if (curr_session->remote_state == BFD_STATE_INIT || curr_session->remote_state == BFD_STATE_UP) {
                            curr_session->local_state = BFD_STATE_UP;
                            pr_debug("BFD session: %s going to UP.\n", curr_params->src_ip);
                        }
                    }
                else {   //curr_session->local_state = BFD_STATE_UP
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                        curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                        curr_session->local_state = BFD_STATE_DOWN;
                        pr_debug("BFD remote: %s signaled going DOWN.\n", curr_params->dst_ip);
                    }
                }
            }

        } //if (ret > 0)
    } // while (true)

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

void tx_timeout_handler(union sigval sv) {

    struct bfd_timer *timer_data = sv.sival_ptr;

    uint32_t jitt_maxpercent;
    uint32_t tx_jitter;
    int c;
    struct bfd_session_params *curr_params = timer_data->sess_params;
    struct bfd_session *curr_session = curr_params->current_session;
    struct bfd_ctrl_packet *pkt = timer_data->pkt;
    libnet_ptag_t *udp_tag = timer_data->udp_tag;
    libnet_t *l = timer_data->l;
    struct itimerspec *tx_ts = timer_data->tx_ts;
    //char t_now[100];

    /* Update packet data */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
        curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
        curr_session->req_min_rx_interval, pkt);

    /* Update UDP header */
    bfd_build_udp(pkt, udp_tag, l);

    /* Send BFD packet on wire */
    c = libnet_write(l);

    if (c == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
    //else
    //    pr_debug("--->[%s] Sent BFD packet: tx_intrvl = %d, state = %s\n", get_time(t_now), curr_session->des_min_tx_interval, state2string(curr_session->local_state));

    /* Apply jitter to TX transmit interval as per section 6.8.7 and start the timer for the next packet */
    jitt_maxpercent = (curr_params->detect_mult == 1) ? 15 : 25;
    //uint32_t curr_percent = ((uint32_t) random() % jitt_maxpercent);
    tx_jitter = (curr_session->des_min_tx_interval * (75 + ((uint32_t) random() % jitt_maxpercent))) / 100;
    //pr_debug("curr_percent: %d, max_percent: %d, tx_jitt: %d\n", curr_percent, jitt_maxpercent, tx_jitter);
    bfd_update_timer(tx_jitter, tx_ts, timer_data);
}