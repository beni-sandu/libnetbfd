#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <signal.h>
#include <time.h>

#include "bfd_packet.h"
#include "bfd_session.h"
#include "libbfd.h"

/* Forward declarations */
void tx_timeout_handler(union sigval sv);

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int recvfrom_timeout(int s, char *buf, int len, int timeout_us, struct sockaddr *src_addr, socklen_t *addrlen, enum bfd_state local_state) {
    fd_set fds;
    int n;
    struct timeval tv;

    /* Set up the file descriptor set */
    FD_ZERO(&fds);
    FD_SET(s, &fds);

    /* Set up the struct timeval for the timeout */
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    /* Wait until timeout or data received.
    TODO: check if this is fast enough or, we should use something like libevent. */
    n = select(s+1, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; // timeout!
    if (n == -1) return -1; // error

    /* We have data in the buffer, so do normal recvfrom */
    return recvfrom(s, buf, len, 0, src_addr, addrlen);
}

/* Entry point of a new BFD session */
void *bfd_session_run(void *args) {

    libnet_t *l;                                /* libnet context */
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];     /* libnet error buffer */
    uint32_t src_ip;                            /* Local IP in binary form */
    uint32_t dst_ip;                            /* Remote IP in binary form */
    char if_name[32];                           /* Local interface used on capturing */
    struct bfd_ctrl_packet pkt;                 /* BFD control packet */
    libnet_ptag_t udp_tag = 0, ip_tag = 0;      /* libnet tags */
    int sockfd;                                 /* UDP socket file descriptor */
    struct sockaddr_in sav4;                    /* IPv4 socket address */
    struct sockaddr_in6 sav6;                   /* IPv6 socket address */
    char recv_buf[100];                         /* Buffer for received packet */
    int numbytesrecv;                           /* Number of received bytes on socket */
    struct bfd_ctrl_packet *bfdp;               /* Pointer to captured BFD packet */
    struct sockaddr_storage src_addr;           /* Temporary socket address of packet source, used for debugging for now */
    socklen_t addr_len;                         /* Size of src_addr */
    uint32_t tx_jitter = 0;
    uint32_t jitt_maxpercent = 0;
    char s[INET6_ADDRSTRLEN];

    struct bfd_timer btimer;
    struct sigevent sev;
    struct itimerspec ts;
    int c;

    /* Useful pointers */
    struct bfd_session_params *curr_params = (struct bfd_session_params *)args;
    struct bfd_session new_session;
    curr_params->current_session = &new_session;
    struct bfd_session *curr_session = curr_params->current_session;
    btimer.sess_params = curr_params;

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
    curr_session->tx_interval = (curr_params->des_min_tx_interval < 1000000) ? 1000000 : curr_params->des_min_tx_interval;
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
                curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_params->des_min_tx_interval,
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
        255,                                                /* TTL */
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

    /* Initial TX timer configuration, we start sending packets at min 1s as per the standard */
    sev.sigev_notify = SIGEV_THREAD;                        /* Notify via thread */
    sev.sigev_notify_function = &tx_timeout_handler;        /* Handler function */
    sev.sigev_notify_attributes = NULL;                     /* Could be pointer to pthread_attr_t structure */
    sev.sigev_value.sival_ptr = &btimer;                    /* Pointer passed to handler */

    /* Configure interval */
    ts.it_interval.tv_sec = curr_session->tx_interval / 1000000;
    ts.it_interval.tv_nsec = curr_session->tx_interval % 1000000 * 1000;
    ts.it_value.tv_sec = curr_session->tx_interval / 1000000;
    ts.it_value.tv_nsec = curr_session->tx_interval % 1000000 * 1000;

    /* Create timer */
    if (timer_create(CLOCK_REALTIME, &sev, &btimer.timer_id) == -1) {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    /* Start timer */
    if (bfd_start_tx_timer(&btimer, &ts) == -1) {
        fprintf(stderr, "bfd_start_timer error\n");
        exit(EXIT_FAILURE);
    }

    /* Create an UDP socket */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Bind it */
    memset(&sav4, 0, sizeof(struct sockaddr_in));
    sav4.sin_family = AF_INET;
    inet_pton(sav4.sin_family, curr_params->src_ip, &(sav4.sin_addr));
    sav4.sin_port = htons(BFD_CTRL_PORT);
    
    if (bind(sockfd, (struct sockaddr *)&sav4, sizeof(sav4)) == -1) {
       perror("bind");
       exit(EXIT_FAILURE);
    }

    btimer.send_next_pkt = 1;
    addr_len = sizeof(src_addr);

    /* Main processing loop, where most of the magic happens */
    while (true) {
        
        /* Send next BFD packet */
        if (btimer.send_next_pkt == 1) {

            /*
            * Apply jitter to TX transmit interval as per section 6.8.7:
            * transmit interval should be randomly jittered between
            * 75% and 100% of nominal value, unless DetectMult is 1, then should be
            * between 75% and 90%. This needs to be done on a per packet basis.
            */
            jitt_maxpercent = (curr_params->detect_mult == 1) ? 15 : 25;
            tx_jitter = (curr_session->tx_interval * (75 + ((uint32_t) random() % jitt_maxpercent))) / 100;
            bfd_update_tx_timer(tx_jitter, &ts, &btimer);

            /*pr_debug("Sending BFD ctrl packet, diag: %d, state: %d, poll: %d, final: %d, detect_mult: %d, my_discr: 0x%x, your_discr: 0x%x, des_min_tx: %d, req_min_tx: %d\n",
                curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final, curr_params->detect_mult, curr_session->local_discr,
                curr_session->remote_discr, curr_params->des_min_tx_interval, curr_session->req_min_rx_interval);*/

            /* Update packet data */
            bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
                curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_params->des_min_tx_interval,
                curr_session->req_min_rx_interval, &pkt);

            /* Update UDP header */
            bfd_build_udp(&pkt, &udp_tag, l);

            /* Send BFD packet on wire */
            c = libnet_write(l);

            if (c == -1) {
                fprintf(stderr, "Write error %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(EXIT_FAILURE);
            } 
            else {
                btimer.send_next_pkt = 0;
            }
        }
        
        /* Receive a BFD packet */
        numbytesrecv = recvfrom_timeout(sockfd, recv_buf, 100 , curr_session->detection_time,
            (struct sockaddr *)&src_addr, &addr_len, curr_session->local_state);
        
        /* Only check for timeout, in which case if the session was UP or INIT, declare it down */
        if (numbytesrecv == -2)
            if (curr_session->local_state == BFD_STATE_UP || curr_session->local_state == BFD_STATE_INIT) {
                curr_session->local_state = BFD_STATE_DOWN;
                curr_session->local_diag = BFD_DIAG_CTRL_DETECT_TIME_EXPIRED;
                pr_debug("Detected BFD remote %s going DOWN.\n", curr_params->dst_ip);
            }
        
        /* TODO: we should probably also check for actual errors from recvfrom, and if we need to handle those somehow */

        /* If we received a packet, go through processing */
        if (numbytesrecv > 0) {

            /* Reception of BFD control packets (section 6.8.6 in RFC5880) */
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
            curr_session->remote_state = (bfdp->byte2.state >> 6) & 0x03;
            curr_session->remote_multipoint = bfdp->byte2.multipoint & 0x01;
            curr_session->remote_auth = (bfdp->byte2.auth_present >> 2) & 0x01;
            curr_session->remote_detect_mult = bfdp->detect_mult;
            curr_session->remote_des_min_tx_interval = ntohl(bfdp->des_min_tx_interval);

            /* If a Poll Sequence is being transmitted by the local system and
            the Final (F) bit in the received packet is set, the Poll Sequence
            MUST be terminated.
            TODO: implement Polling sequence */

            /* Update the transmit interval as per section 6.8.2 */
            curr_session->tx_interval = max(curr_session->tx_interval, curr_session->remote_min_rx_interval);
        
            /* Update the Detection Time as per section 6.8.4 */
            curr_session->detection_time = curr_session->remote_detect_mult * curr_session->remote_des_min_tx_interval;

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
                else    //curr_session->local_state = BFD_STATE_UP
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                            curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                            curr_session->local_state = BFD_STATE_DOWN;
                            pr_debug("BFD remote: %s signaled going DOWN.\n", curr_params->dst_ip);
                    }
            }
        
        /* TODO: If the Poll (P) bit is set, send a BFD Control packet to the
        remote system with the Poll (P) bit clear, and the Final (F) bit
        set (see section 6.8.7). */

        } //if (numbytesrecv > 0)
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

    timer_data->send_next_pkt = 1;
}