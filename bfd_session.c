/*
 * Copyright (C) 2022 Beniamin Sandu <beniaminsandu@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
#include "libnetbfd.h"

#define max(a, b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

/* Globals */
pthread_mutex_t port_lock = PTHREAD_MUTEX_INITIALIZER;
static uint16_t src_port = BFD_SRC_PORT_MIN;
extern struct bfd_session_node *head;
extern pthread_rwlock_t rwlock;

/* Per thread variables */
__thread libnet_t *l;                                        /* libnet context */
__thread char libnet_errbuf[LIBNET_ERRBUF_SIZE];             /* libnet error buffer */
__thread uint32_t src_ipv4;                                  /* Local IPv4 in binary form */
__thread uint32_t dst_ipv4;                                  /* Remote IPv4 in binary form */
__thread struct libnet_in6_addr dst_ipv6;                    /* Remote IPv6 in binary form */
__thread struct libnet_in6_addr src_ipv6;                    /* Local IPv6 in binary form */
__thread struct bfd_ctrl_packet pkt;                         /* BFD control packet that we send */
__thread libnet_ptag_t udp_tag = 0, ip_tag = 0;              /* libnet tags */
__thread int sockfd;                                         /* UDP socket file descriptor */
__thread struct sockaddr_in sav4;                            /* IPv4 socket address */
__thread struct sockaddr_in6 sav6;                           /* IPv6 socket address */
__thread int ret;                                            /* Number of received bytes on socket */
__thread struct bfd_ctrl_packet *bfdp;                       /* Pointer to BFD packet received from remote peer */
__thread cap_t caps;
__thread cap_flag_value_t cap_val;
__thread struct cb_status callback_status;
__thread int ns_fd;
__thread char ns_buf[MAX_PATH] = "/run/netns/";
__thread struct bfd_timer tx_timer;
__thread struct sigevent tx_sev;
__thread struct itimerspec tx_ts;
__thread struct bfd_session_node session_node;
__thread struct bfd_session_params session_parameters;      /* Copy of the session parameters */
__thread char if_name[IFNAMSIZ];

/* Forward declarations */
void tx_timeout_handler(union sigval sv);
void thread_cleanup(void *args);
int recvmsg_ppoll(int sockfd, struct msghdr *recv_hdr, int timeout_us);
void *bfd_session_run(void *args);

int recvmsg_ppoll(int sockfd, struct msghdr *recv_hdr, int timeout_us)
{
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
            return recvmsg(sockfd, recv_hdr, 0);

    return EXIT_FAILURE;
}

/* Entry point of a new BFD session */
void *bfd_session_run(void *args)
{
    /* Get a pointer to data passed to session start interface */
    struct bfd_thread *current_thread = (struct bfd_thread *)args;

    /* Copy the session parameters */
    memset(&session_parameters, 0, sizeof(struct bfd_session_params));
    memcpy(&session_parameters, current_thread->session_params, sizeof(struct bfd_session_params));

    /* Replace the pointer with one to our copy */
    current_thread->session_params = &session_parameters;

    /* Setup some more useful pointers */
    struct bfd_session_params *curr_params = &session_parameters;
    struct bfd_session new_session;
    curr_params->current_session = &new_session;
    struct bfd_session *curr_session = curr_params->current_session;

    sem_post(&current_thread->s_id_sem);

    /* Setup buffer and header structs for received packets */
    uint8_t recv_buf[BFD_PKG_MIN_SIZE];
    struct iovec recv_iov[1] = { { recv_buf, sizeof(recv_buf) } };
    uint8_t recv_ctrldata[CMSG_SPACE(sizeof(uint8_t))];
    struct msghdr recv_hdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = recv_iov,
        .msg_iovlen = 1,
        .msg_control = recv_ctrldata,
        .msg_controllen = sizeof(recv_ctrldata)
    };
    int flag_enable = 1;

    /* Initialize timer data */
    tx_timer.sess_params = curr_params;
    tx_timer.pkt = &pkt;
    tx_timer.udp_tag = &udp_tag;
    tx_timer.tx_ts = &tx_ts;
    tx_timer.timer_id = NULL;
    tx_timer.is_timer_created = false;
    tx_timer.is_session_configured = false;

    /*
     * Define some callback return codes here to cover cases that we're interested in (can be adjusted later if needed):
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
     *  6 - Source IP is not assigned, or the interface that is using it is DOWN
     */
    callback_status.cb_ret = 0;
    callback_status.session_params = curr_params;

    pthread_cleanup_push(thread_cleanup, (void*)&tx_timer);

    /* Check for CAP_NET_RAW capability */
    caps = cap_get_proc();
    if (caps == NULL) {
        perror("cap_get_proc");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_val) == -1) {
        perror("cap_get_flag");
        cap_free(caps);
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    if (cap_val != CAP_SET) {
        cap_free(caps);
        fprintf(stderr, "Execution requires CAP_NET_RAW capability.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* We don't need this anymore, so clean it */
    cap_free(caps);

    /* Configure network namespace */
    if (strlen(curr_params->net_ns) != 0) {
        strcat(ns_buf, curr_params->net_ns);

        ns_fd = open(ns_buf, O_RDONLY);

        if (ns_fd == -1) {
            perror("open ns fd");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (setns(ns_fd, CLONE_NEWNET) == -1) {
            perror("set ns");
            close(ns_fd);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        close(ns_fd);
    }

    /* Check if provided IP addresses are valid before doing anything else with them */
    if (curr_params->is_ipv6 == true) {
        if (is_ip_valid(curr_params->src_ip, true) == false) {
            fprintf(stderr, "Invalid source IPv6 address: %s\n", curr_params->src_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (is_ip_valid(curr_params->dst_ip, true) == false) {
            fprintf(stderr, "Invalid destination IPv6 address: %s\n", curr_params->dst_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    } else {
        if (is_ip_valid(curr_params->src_ip, false) == false) {
            fprintf(stderr, "Invalid source IPv4 address: %s\n", curr_params->src_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (is_ip_valid(curr_params->dst_ip, false) == false) {
            fprintf(stderr, "Invalid destination IPv4 address: %s\n", curr_params->dst_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /* Make sure source/destination IPs are different */
    if (strcmp(curr_params->src_ip, curr_params->dst_ip) == 0) {
        fprintf(stderr, "Cannot use same IP address for both source/destination.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /*
     * Check if source IP address is assigned on the local machine and if
     * the interface is UP.
     */

    if (curr_params->is_ipv6 == true) {
        if (is_ip_live(curr_params->src_ip, true, if_name) == false) {
            pr_debug("Provided source IP is not assigned or the interface is DOWN.\n");

            if (curr_params->callback != NULL) {
                callback_status.cb_ret = 6;
                curr_params->callback(&callback_status);
            }
        }
    } else {
        if (is_ip_live(curr_params->src_ip, false, if_name) == false) {
            pr_debug("Provided source IP is not assigned or the interface is DOWN.\n");

            if (curr_params->callback != NULL) {
                callback_status.cb_ret = 6;
                curr_params->callback(&callback_status);
            }
        }
    }

    /* Save pointer to interface name */
    curr_session->if_name = if_name;

    /* Create an UDP socket */
    if (curr_params->is_ipv6 == true) {
        if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }
    else {
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /* Store the sockfd so we can close it when we're done */
    tx_timer.sess_params->current_session->sockfd = sockfd;

    /* Configure socket to read TTL value */
    if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL, &flag_enable, sizeof(flag_enable)) < 0) {
        fprintf(stderr, "Can't configure socket to read TTL.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Make socket address reusable */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag_enable, sizeof(flag_enable)) < 0) {
        fprintf(stderr, "Can't configure socket address to be reused.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Bind the socket */
    if (curr_params->is_ipv6 == true) {
        memset(&sav6, 0, sizeof(struct sockaddr_in6));
        sav6.sin6_family = AF_INET6;
        inet_pton(sav6.sin6_family, curr_params->src_ip, &(sav6.sin6_addr));
        sav6.sin6_port = htons(BFD_CTRL_PORT);

        if (bind(sockfd, (struct sockaddr *)&sav6, sizeof(sav6)) == -1) {
            perror("bind");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }
    else {
        memset(&sav4, 0, sizeof(struct sockaddr_in));
        sav4.sin_family = AF_INET;
        inet_pton(sav4.sin_family, curr_params->src_ip, &(sav4.sin_addr));
        sav4.sin_port = htons(BFD_CTRL_PORT);

        if (bind(sockfd, (struct sockaddr *)&sav4, sizeof(sav4)) == -1) {
            perror("bind");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /*
     * If for example we have a veth pair in the same namespace, we can't bind libnet to a
     * specific device, since it will get confused and not work properly. I suspect this happens
     * because the veth peer will appear as a parent ID device and it cannot distinguish between
     * them.
     * 
     * Although this is not a very realistic scenario, it can be useful for quick testing sometimes,
     * so as a workaround, if destination IP is assigned on the local machine inside the same
     * network namespace, don't specifically bind libnet to that device.
     */
    if (curr_params->is_ipv6 == true) {
        if (is_ip_live(curr_params->dst_ip, true, NULL) == true) {
            pr_debug("Destination IP is on same machine/namespace.\n");
            l = libnet_init(
                LIBNET_RAW6,                                /* injection type */
                NULL,                                       /* network interface */
                libnet_errbuf);                             /* error buffer */
        } else
            l = libnet_init(
                LIBNET_RAW6,                                /* injection type */
                if_name,                                    /* network interface */
                libnet_errbuf);                             /* error buffer */

        if (l == NULL) {
            fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        /* Convert IP strings to network format */
        src_ipv6 = libnet_name2addr6(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);
        dst_ipv6 = libnet_name2addr6(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE);
    }
    else {
        if (is_ip_live(curr_params->dst_ip, false, NULL) == true) {
            pr_debug("Destination IP is on same machine/namespace.\n");
            l = libnet_init(
                LIBNET_RAW4,                                /* injection type */
                NULL,                                       /* network interface */
                libnet_errbuf);                             /* error buffer */
        } else
            l = libnet_init(
                LIBNET_RAW4,                                /* injection type */
                if_name,                                    /* network interface */
                libnet_errbuf);                             /* error buffer */

        if (l == NULL) {
            fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        /* Convert IP strings to network format */
        src_ipv4 = libnet_name2addr4(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);
        dst_ipv4 = libnet_name2addr4(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE);
    }

    /* Copy libnet pointer */
    tx_timer.l = l;

    /* Seed random generator used for local discriminator */
    srandom((uint64_t)curr_params);

    /* Configure initial values for the new BFD session */
    curr_session->des_min_tx_interval = curr_params->des_min_tx_interval;
    curr_session->req_min_rx_interval = curr_params->req_min_rx_interval;
    curr_session->op_tx = (curr_params->des_min_tx_interval < 1000000) ? 1000000 : curr_params->des_min_tx_interval;
    curr_session->local_diag = BFD_DIAG_NODIAG;
    curr_session->local_discr = (uint32_t)(random());
    curr_session->local_state = BFD_STATE_DOWN;
    curr_session->remote_discr = 0;
    curr_session->remote_min_rx_interval = 1;
    curr_session->remote_state = BFD_STATE_DOWN;
    curr_session->detection_time = 1000000;
    curr_session->local_poll = false;
    curr_session->local_final = false;
    curr_session->poll_in_progress = false;
    curr_session->final_detection_time = 0;
    curr_session->final_op_tx = 0;
    curr_session->dst_port = BFD_CTRL_PORT;
    curr_session->dscp = curr_params->dscp;
    curr_session->detect_mult = curr_params->detect_mult;

    /* Configure session source port */
    if (curr_params->src_port > 0)
        curr_session->src_port = curr_params->src_port;
    else {
        pthread_mutex_lock(&port_lock);
        curr_session->src_port = src_port++;
        pthread_mutex_unlock(&port_lock);
    }

    /* Build initial BFD control packet */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
                curr_session->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
                curr_session->req_min_rx_interval, &pkt);

    /* Build UDP header */
    udp_tag = libnet_build_udp(
        curr_session->src_port,                                 /* Source port */
        BFD_CTRL_PORT,                                          /* Destination port */
        LIBNET_UDP_H + BFD_PKG_MIN_SIZE,                        /* Packet lenght */
        0,                                                      /* Checksum */
        (uint8_t *)&pkt,                                        /* Payload */
        BFD_PKG_MIN_SIZE,                                       /* Payload size */
        l,                                                      /* libnet handle */
        udp_tag);                                               /* libnet tag */

    if (udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Build IP header */
    if (curr_params->is_ipv6 == true) {
        ip_tag = libnet_build_ipv6(
            (curr_session->dscp << 2) & 0xFC,                   /* DSCP */
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
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }
    else {
        ip_tag = libnet_build_ipv4(
            LIBNET_IPV4_H + BFD_PKG_MIN_SIZE + LIBNET_UDP_H,    /* Packet length */
            (curr_session->dscp << 2) & 0xFC,                   /* DSCP */
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
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
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
    if (timer_create(CLOCK_REALTIME, &tx_sev, &(tx_timer.timer_id)) == -1) {
        perror("timer_create");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Timer should be created, but we still get a NULL pointer sometimes */
    tx_timer.is_timer_created = true;
    pr_debug("TX timer ID: %p\n", tx_timer.timer_id);

    /* Copy params pointer to session node */
    session_node.session_params = curr_params;

    /* Add the session to the list */
    pthread_rwlock_wrlock(&rwlock);
    bfd_add_session(&head, &session_node);
    pthread_rwlock_unlock(&rwlock);

    /* Session configuration is successful, return a valid session id */
    tx_timer.is_session_configured = true;
    sem_post(&current_thread->sem);

    /* Start sending packets at min 1s rate */
    bfd_update_timer(curr_session->op_tx, &tx_ts, &tx_timer);

#ifdef DEBUG_ENABLE
    libnet_diag_dump_context(l);
#endif

    /* Loop for processing incoming packets */
    while (true) {

        /* Check for any session parameter change below */

        /* Check for new detect_mult */
        if ((curr_params->detect_mult != curr_session->detect_mult) && curr_params->detect_mult > 0) {
            pr_debug("Change of detect_mult requested, new value: %d\n", curr_params->detect_mult);
            curr_session->detect_mult = curr_params->detect_mult;
        }

        /* Check for new DSCP value */
        if ((curr_params->dscp != curr_session->dscp) && curr_params->dscp > 0) {
            pr_debug("Change of DSCP value requested, new value: %d\n", curr_params->dscp);
            curr_session->dscp = curr_params->dscp;

            /* Rebuild IP header with new DSCP */
            if (curr_params->is_ipv6 == true) {
                ip_tag = libnet_build_ipv6(
                    (curr_session->dscp << 2) & 0xFC,                   /* DSCP */
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
                        continue;
                    }
            } else {
                ip_tag = libnet_build_ipv4(
                    LIBNET_IPV4_H + BFD_PKG_MIN_SIZE + LIBNET_UDP_H,    /* Packet length */
                    (curr_session->dscp << 2) & 0xFC,                   /* DSCP */
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
                    continue;
                }
            }
        }

        /* Check our socket for data */
        ret = recvmsg_ppoll(sockfd, &recv_hdr, curr_session->detection_time);

        /* No data available */
        if (ret == -2) {

            /* If we did not get any reponse and session was UP or INIT, bring it down */
            if (curr_session->local_state == BFD_STATE_UP || curr_session->local_state == BFD_STATE_INIT) {
                curr_session->local_state = BFD_STATE_DOWN;
                curr_session->local_diag = BFD_DIAG_CTRL_DETECT_TIME_EXPIRED;

                /* Adjust the operational TX to min 1s rate */
                if (curr_session->op_tx < 1000000)
                    curr_session->op_tx = 1000000;

                /* Clear remote discriminator value */
                curr_session->remote_discr = 0;

                if (curr_params->callback != NULL) {
                    callback_status.cb_ret = 1;
                    curr_params->callback(&callback_status);
                }
            }
        }

        /* We have some data, get it and process it */
        if (ret > 0) {

            /* If TTL/Hop limit is not 255, packet MUST be discarded (section 5 in RFC5881) */
            if (get_ttl(&recv_hdr) != 255) {
                pr_debug("Wrong TTL value for received packet.\n");
                continue;
            }

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
            curr_session->remote_poll = (bfdp->byte2.poll >> 5) & 0x01;
            curr_session->remote_final = (bfdp->byte2.final >> 4) & 0x01;

            /*
             * If a Poll Sequence is being transmitted by the local system and the Final (F) bit
             * in the received packet is set, the Poll Sequence MUST be terminated.
             */
            if (curr_session->poll_in_progress == true && curr_session->remote_final == true) {
                pr_debug("Finishing poll Sequence with remote: %s\n", curr_params->dst_ip);
                curr_session->poll_in_progress = false;
                curr_session->local_poll = false;
            }

            /* If parameter change was delayed, adjust it here */
            if (curr_session->final_op_tx != 0) {
                curr_session->op_tx = curr_session->final_op_tx;
                curr_session->final_op_tx = 0;
                curr_session->des_min_tx_interval = curr_params->des_min_tx_interval;
            }

            if (curr_session->final_detection_time != 0) {
                curr_session->detection_time = curr_session->final_detection_time;
                curr_session->final_detection_time = 0;
                curr_session->req_min_rx_interval = curr_params->req_min_rx_interval;
            }

            /* Update the operational transmit interval as per section 6.8.2 */
            /*
             * If the DesiredMinTxInterval is increased and session state is UP, the actual operation TX interval
             * must not change until the Poll Sequence is finished.
             */
            if ((curr_params->des_min_tx_interval > curr_session->des_min_tx_interval) && curr_session->local_state == BFD_STATE_UP) {
                curr_session->final_op_tx = max(curr_params->des_min_tx_interval, curr_session->remote_min_rx_interval);
            }
            else if ((curr_params->des_min_tx_interval < curr_session->des_min_tx_interval) && curr_session->local_state == BFD_STATE_UP)
                curr_session->des_min_tx_interval = curr_params->des_min_tx_interval;
            curr_session->op_tx = max(curr_session->des_min_tx_interval, curr_session->remote_min_rx_interval);

            /* Update the Detection Time as per section 6.8.4 */
             /*
             * If the RequiredMinRxInterval is decreased and session state is UP, the detection time
             * must not change until the Poll Sequence is finished.
             */
            if ((curr_params->req_min_rx_interval < curr_session->req_min_rx_interval) && curr_session->local_state == BFD_STATE_UP) {
                curr_session->final_detection_time = curr_session->remote_detect_mult * max(curr_params->req_min_rx_interval, curr_session->remote_des_min_tx_interval);
            }
            else if ((curr_params->req_min_rx_interval > curr_session->req_min_rx_interval) && curr_session->local_state == BFD_STATE_UP)
                curr_session->req_min_rx_interval = curr_params->req_min_rx_interval;
            curr_session->detection_time = curr_session->remote_detect_mult * max(curr_session->req_min_rx_interval, curr_session->remote_des_min_tx_interval);

            /* BFD state machine logic */
            if (curr_session->local_state == BFD_STATE_ADMIN_DOWN) {
                continue;
            }

            if (curr_session->remote_state == BFD_STATE_ADMIN_DOWN) {
                if (curr_session->local_state != BFD_STATE_DOWN) {
                    curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                    curr_session->local_state = BFD_STATE_DOWN;
                    if (curr_params->callback != NULL) {
                        callback_status.cb_ret = 5;
                        curr_params->callback(&callback_status);
                    }
                }
            }
            else {
                if (curr_session->local_state == BFD_STATE_DOWN) {
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                        curr_session->local_state = BFD_STATE_INIT;
                        if (curr_params->callback != NULL) {
                            callback_status.cb_ret = 2;
                            curr_params->callback(&callback_status);
                        }
                    }
                    else if (curr_session->remote_state == BFD_STATE_INIT) {
                        curr_session->local_state = BFD_STATE_UP;
                        curr_session->local_diag = BFD_DIAG_NODIAG;  // should this be updated?
                        if (curr_params->callback != NULL) {
                            callback_status.cb_ret = 3;
                            curr_params->callback(&callback_status);
                        }
                    }
                }
                else if (curr_session->local_state == BFD_STATE_INIT) {
                        if (curr_session->remote_state == BFD_STATE_INIT || curr_session->remote_state == BFD_STATE_UP) {
                            curr_session->local_state = BFD_STATE_UP;
                            curr_session->local_diag = BFD_DIAG_NODIAG; // should this be updated?
                            if (curr_params->callback != NULL) {
                                callback_status.cb_ret = 3;
                                curr_params->callback(&callback_status);
                            }
                        }
                    }
                else {   //curr_session->local_state = BFD_STATE_UP
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                        curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                        curr_session->local_state = BFD_STATE_DOWN;
                        if (curr_params->callback != NULL) {
                                callback_status.cb_ret = 4;
                                curr_params->callback(&callback_status);
                        }
                    }
                }
            }

            /*
             * If the Poll (P) bit is set, send a BFD Control packet to the remote system
             * with the Poll (P) bit clear, and the Final (F) bit set.
             * This has to be done as soon as practicable, without respect to the transmission timer.
             */
            if (curr_session->remote_poll == true) {

                int c = 0;

                curr_session->local_poll = false;
                curr_session->local_final = true;

                /* Update packet data */
                bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
                    curr_session->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
                    curr_session->req_min_rx_interval, &pkt);

                /* Update UDP header */
                bfd_build_udp(&pkt, curr_session->src_port, &udp_tag, l);

                /* Send BFD packet on wire */
                c = libnet_write(l);

                if (c == -1) {
                    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
                    continue;
                }

                /* We only send 1 packet with the Final (F) bit set, so flip it back */
                curr_session->local_final = false;
            }

        } //if (ret > 0)
    } // while (true)

    pthread_cleanup_pop(0);

    /* Should never reach this point */
    return NULL;
}

/*
 * Create a new BFD session, returns a session id
 * on successful creation, -1 otherwise
 */
bfd_session_id bfd_session_start(struct bfd_session_params *params)
{
    pthread_t session_id;
    int ret;
    struct bfd_thread new_thread;

    new_thread.session_params = params;
    new_thread.ret = 0;

    sem_init(&new_thread.sem, 0, 0);
    sem_init(&new_thread.s_id_sem, 0, 0);

    ret = pthread_create(&session_id, NULL, bfd_session_run, (void *)&new_thread);

    if (ret) {
        fprintf(stderr, "bfd_session_create for IP: %s failed, err: %d\n", params->src_ip, ret);
        return -1;
    }

    sem_wait(&new_thread.s_id_sem);

    /* Copy the session id */
    new_thread.session_params->current_session->session_id = session_id;

    sem_wait(&new_thread.sem);

    if (new_thread.ret != 0)
        return new_thread.ret;

    return session_id;
}

/* Stop a BFD session */
void bfd_session_stop(bfd_session_id session_id)
{
    if (session_id > 0) {

        /* Remove session from list */
        pthread_rwlock_wrlock(&rwlock);
        bfd_remove_session(&head, session_id);
        pthread_rwlock_unlock(&rwlock);

        pr_debug("Stopping BFD session: %ld\n", session_id);
        pthread_cancel(session_id);
        pthread_join(session_id, NULL);
    }
}

void tx_timeout_handler(union sigval sv)
{
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

    if (curr_session->poll_in_progress == true)
        curr_session->local_poll = true;

    /* Update packet data */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
        curr_session->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
        curr_session->req_min_rx_interval, pkt);

    /* Update UDP header */
    bfd_build_udp(pkt, curr_session->src_port, udp_tag, l);

    /* Send BFD packet on wire */
    c = libnet_write(l);

    if (c == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        pthread_exit(NULL);
    }

    /* Apply jitter to TX transmit interval as per section 6.8.7 and start the timer for the next packet */
    jitt_maxpercent = (curr_session->detect_mult == 1) ? 15 : 25;
    tx_jitter = (curr_session->op_tx * (75 + ((uint32_t) random() % jitt_maxpercent))) / 100;
    bfd_update_timer(tx_jitter, tx_ts, timer_data);
}

void thread_cleanup(void *args)
{
    struct bfd_timer *timer = (struct bfd_timer *)args;

    /* Cleanup allocated data */
    if (timer->is_timer_created == true) {
        timer_delete(timer->timer_id);

        /*
         * Temporary workaround for C++ programs, seems sometimes the timer doesn't
         * get disarmed in time, and tries to use memory that was already freed.
         */
        usleep(100000);
    }

    if (timer->l != NULL)
        libnet_destroy(timer->l);

    if (timer->sess_params->current_session->sockfd != 0)
        close(timer->sess_params->current_session->sockfd);

    /*
     * If a session is not successfully configured, we don't call pthread_join on it,
     * only exit using pthread_exit. Calling pthread_detach here should automatically
     * release resources for unconfigured sessions.
     */
    if (timer->is_session_configured == false)
        pthread_detach(pthread_self());
}
