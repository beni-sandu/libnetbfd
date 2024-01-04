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
#include <ifaddrs.h>

#include "../include/bfd_packet.h"
#include "../include/bfd_session.h"
#include "../include/libnetbfd.h"

#define max(a, b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

/* Globals */
static pthread_mutex_t port_lock = PTHREAD_MUTEX_INITIALIZER;
static uint16_t src_port = BFD_SRC_PORT_MIN;
extern struct bfd_session_node *head;
extern pthread_rwlock_t read_lock;
extern pthread_rwlock_t write_lock;

/* Per thread variables */
static __thread libnet_t *l;                                        /* libnet context */
static __thread char libnet_errbuf[LIBNET_ERRBUF_SIZE];             /* libnet error buffer */
static __thread uint32_t src_ipv4;                                  /* Local IPv4 in binary form */
static __thread uint32_t dst_ipv4;                                  /* Remote IPv4 in binary form */
static __thread struct libnet_in6_addr dst_ipv6;                    /* Remote IPv6 in binary form */
static __thread struct libnet_in6_addr src_ipv6;                    /* Local IPv6 in binary form */
static __thread struct bfd_ctrl_packet pkt;                         /* BFD control packet that we send */
static __thread libnet_ptag_t udp_tag = 0, ip_tag = 0;              /* libnet tags */
static __thread int sockfd;                                         /* UDP socket file descriptor */
static __thread struct sockaddr_in sav4;                            /* IPv4 socket address */
static __thread struct sockaddr_in6 sav6;                           /* IPv6 socket address */
static __thread int ret;                                            /* Number of received bytes on socket */
static __thread struct bfd_ctrl_packet *bfdp;                       /* Pointer to BFD packet received from remote peer */
static __thread cap_t caps;
static __thread cap_flag_value_t cap_val;
static __thread struct cb_status callback_status;
static __thread int ns_fd;
static __thread char ns_buf[MAX_PATH] = "/run/netns/";
static __thread struct bfd_timer tx_timer;
static __thread struct sigevent tx_sev;
static __thread struct itimerspec tx_ts;
static __thread struct bfd_session_node session_node;
static __thread struct bfd_session_params session_parameters;      /* Copy of the session parameters */
static __thread char if_name[IFNAMSIZ];

/* Forward declarations */
static void tx_timeout_handler(union sigval sv);
static void thread_cleanup(void *args);
static ssize_t recvmsg_ppoll(int sockfd, struct msghdr *recv_hdr, uint64_t timeout_us);
static void *bfd_session_run(void *args);
static void bfd_reset_session_state_vars(struct bfd_session *session);
static void bfd_add_session_to_list(struct bfd_session_node **head_ref, struct bfd_session_node *new_node);
static void bfd_remove_session_from_list(struct bfd_session_node **head_ref, bfd_session_id session_id);
static int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *timer_data);
static bool is_ip_valid(char *ip, bool is_ipv6);
static int get_ttl_or_hopl(struct msghdr *recv_msg, bool is_ipv6);
static int is_ip_live(char *ip_addr, bool is_ipv6, char *if_name);

static ssize_t recvmsg_ppoll(int sockfd, struct msghdr *recv_hdr, uint64_t timeout_us)
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
        bfd_pr_error(NULL, "ppoll"); //error in ppoll call
        return -1;
    } else if (ret == 0) {
        return -2; //timeout expired
    } else
        if (fds[0].revents & POLLIN)
            return recvmsg(sockfd, recv_hdr, 0);

    return -1;
}

/* Entry point of a new BFD session */
static void *bfd_session_run(void *args)
{
    /* Get a pointer to data passed to session start interface */
    struct bfd_thread *current_thread = (struct bfd_thread *)args;

    /* Copy the session parameters */
    memset(&session_parameters, 0, sizeof(struct bfd_session_params));
    memcpy(&session_parameters, current_thread->session_params, sizeof(struct bfd_session_params));

    /* Setup some more useful pointers */
    struct bfd_session_params *curr_params = &session_parameters;
    struct bfd_session new_session;
    session_node.current_session = &new_session;
    struct bfd_session *curr_session = session_node.current_session;
    curr_session->session_timer = &tx_timer;
    curr_session->pkt = &pkt;
    curr_session->udp_tag = &udp_tag;
    curr_session->is_configured = false;

    /* Replace the pointers with our copy */
    current_thread->session_params = &session_parameters;
    current_thread->current_session = curr_session;

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
    int ip_ret = -1;

    /* Initialize timer data */
    tx_timer.tx_ts = &tx_ts;
    tx_timer.timer_id = NULL;
    tx_timer.is_created = false;

    /* Initialize other session data */
    curr_session->l = NULL;
    curr_session->sockfd = 0;

    /*
     * Define some callback return codes here to cover cases that we're interested in (can be adjusted later if needed):
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
     *  6 - Interface that is using the source IP is DOWN
     *  7 - Session is going into ADMIN_DOWN state
     *  8 - Session is getting out of ADMIN_DOWN state
     *  9 - Provided source IP is not assigned on any interface
     */
    callback_status.cb_ret = BFD_CB_DEFAULT;
    callback_status.session_params = curr_params;
    curr_session->curr_sess_cb_status = &callback_status;

    sem_post(&current_thread->s_id_sem);

    pthread_cleanup_push(thread_cleanup, (void*)curr_session);

    /* Check if the required BFD specific parameters are valid */
    if (curr_params->detect_mult <= 0) {
        bfd_pr_error(curr_params->log_file, "Invalid Detection Multiplier value.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    if (curr_params->req_min_rx_interval <= 0) {
        bfd_pr_error(curr_params->log_file, "Invalid Required Min RX value.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    if (curr_params->des_min_tx_interval <= 0) {
        bfd_pr_error(curr_params->log_file, "Invalid Desired Min TX value.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Check for CAP_NET_RAW capability */
    caps = cap_get_proc();
    if (caps == NULL) {
        bfd_pr_error(curr_params->log_file, "cap_get_proc");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_val) == -1) {
        bfd_pr_error(curr_params->log_file, "cap_get_flag");
        cap_free(caps);
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    if (cap_val != CAP_SET) {
        cap_free(caps);
        bfd_pr_error(curr_params->log_file, "Execution requires CAP_NET_RAW capability.\n");
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
            bfd_pr_error(curr_params->log_file, "Cannot open namespace descriptor.\n");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (setns(ns_fd, CLONE_NEWNET) == -1) {
            bfd_pr_error(curr_params->log_file, "Cannot set namespace.\n");
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
            bfd_pr_error(curr_params->log_file, "Invalid source IPv6 address: %s\n", curr_params->src_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (is_ip_valid(curr_params->dst_ip, true) == false) {
            bfd_pr_error(curr_params->log_file, "Invalid destination IPv6 address: %s\n", curr_params->dst_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    } else {
        if (is_ip_valid(curr_params->src_ip, false) == false) {
            bfd_pr_error(curr_params->log_file, "Invalid source IPv4 address: %s\n", curr_params->src_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (is_ip_valid(curr_params->dst_ip, false) == false) {
            bfd_pr_error(curr_params->log_file, "Invalid destination IPv4 address: %s\n", curr_params->dst_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /* Make sure source/destination IPs are different */
    if (strcmp(curr_params->src_ip, curr_params->dst_ip) == 0) {
        bfd_pr_error(curr_params->log_file, "Cannot use same IP address for both source/destination.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /*
     * Check if source IP address is assigned on the local machine and if
     * the interface is UP.
     */
    ip_ret = is_ip_live(curr_params->src_ip, curr_params->is_ipv6, if_name);
    if (ip_ret == 1) {
        bfd_pr_error(curr_params->log_file, "Interface using the source IP is down.\n");

        if (curr_params->callback != NULL) {
            callback_status.cb_ret = BFD_CB_INTERFACE_DOWN;
            curr_params->callback(&callback_status);
        }
    } else if (ip_ret == -1) {
        bfd_pr_error(curr_params->log_file, "Source IP not assigned on any interface.\n");

        if (curr_params->callback != NULL) {
            callback_status.cb_ret = BFD_CB_SRC_IP_NOT_ASSIGNED;
            curr_params->callback(&callback_status);
        }

        /* If IP is not assigned, we should just exit now, since the socket bind will fail below anyway */
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Save pointer to interface name */
    curr_session->if_name = if_name;

    /* Create an UDP socket */
    if (curr_params->is_ipv6 == true) {
        if ((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            bfd_pr_error(curr_params->log_file, "Cannot create UDP socket.\n");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }
    else {
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            bfd_pr_error(curr_params->log_file, "Cannot create UDP socket.\n");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /* Store the sockfd so we can close it when we're done */
    curr_session->sockfd = sockfd;

    /* Configure socket to read TTL/Hop Limit value */
    if (curr_params->is_ipv6 == true) {
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &flag_enable, sizeof(flag_enable)) < 0) {
            bfd_pr_error(curr_params->log_file, "Can't configure socket to read Hop Limit value.\n");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    } else {
        if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL, &flag_enable, sizeof(flag_enable)) < 0) {
            bfd_pr_error(curr_params->log_file, "Can't configure socket to read TTL value.\n");
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /* Make socket address reusable */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag_enable, sizeof(flag_enable)) < 0) {
        bfd_pr_error(curr_params->log_file, "Can't configure socket address to be reused.\n");
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
            bfd_pr_error(curr_params->log_file, "Cannot bind socket.\n");
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
            bfd_pr_error(curr_params->log_file, "Cannot bind socket.\n");
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
        if (is_ip_live(curr_params->dst_ip, true, NULL) != -1) {
            bfd_pr_debug(curr_params->log_file, "Destination IP is on same machine/namespace.\n");
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
            bfd_pr_error(curr_params->log_file, "libnet_init() failed: %s\n", libnet_errbuf);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        /* Convert IP strings to network format */
        src_ipv6 = libnet_name2addr6(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);
        dst_ipv6 = libnet_name2addr6(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE);
    }
    else {
        if (is_ip_live(curr_params->dst_ip, false, NULL) != -1) {
            bfd_pr_debug(curr_params->log_file, "Destination IP is on same machine/namespace.\n");
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
            bfd_pr_error(curr_params->log_file, "libnet_init() failed: %s\n", libnet_errbuf);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        /* Convert IP strings to network format */
        src_ipv4 = libnet_name2addr4(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);
        dst_ipv4 = libnet_name2addr4(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE);
    }

    /* Copy libnet pointer */
    curr_session->l = l;

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
    curr_session->remote_poll_in_progress = false;
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
        bfd_pr_error(curr_params->log_file, "Can't build UDP header: %s\n", libnet_geterror(l));
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
            bfd_pr_error(curr_params->log_file, "Can't build IP header: %s\n", libnet_geterror(l));
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
            bfd_pr_error(curr_params->log_file, "Can't build IP header: %s\n", libnet_geterror(l));
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
    }

    /* Initial TX timer configuration, we start sending packets at min 1s as per the standard */
    tx_sev.sigev_notify = SIGEV_THREAD;                         /* Notify via thread */
    tx_sev.sigev_notify_function = &tx_timeout_handler;         /* Handler function */
    tx_sev.sigev_notify_attributes = NULL;                      /* Could be pointer to pthread_attr_t structure */
    tx_sev.sigev_value.sival_ptr = curr_session;                /* Pointer passed to handler */

    /* Configure TX interval */
    tx_ts.it_interval.tv_sec = curr_session->des_min_tx_interval / 1000000;
    tx_ts.it_interval.tv_nsec = curr_session->des_min_tx_interval % 1000000 * 1000;
    tx_ts.it_value.tv_sec = curr_session->des_min_tx_interval / 1000000;
    tx_ts.it_value.tv_nsec = curr_session->des_min_tx_interval % 1000000 * 1000;

    /* Create TX timer */
    if (timer_create(CLOCK_MONOTONIC, &tx_sev, &(tx_timer.timer_id)) == -1) {
        bfd_pr_error(curr_params->log_file, "Cannot create TX timer.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* Timer should be created, but we still get a NULL pointer sometimes */
    tx_timer.is_created = true;

    /* Copy params pointer to session node */
    session_node.session_params = curr_params;

    /* Add the session to the list */
    pthread_rwlock_wrlock(&write_lock);
    bfd_add_session_to_list(&head, &session_node);
    pthread_rwlock_unlock(&write_lock);

    /* Session configuration is successful, return a valid session id */
    curr_session->is_configured = true;
    sem_post(&current_thread->sem);

    /* Start sending packets at min 1s rate */
    bfd_update_timer(curr_session->op_tx, &tx_ts, &tx_timer);

#ifdef DEBUG_ENABLE
    bfd_session_print_stats(pthread_self());
#endif

    /* Loop for processing incoming packets */
    while (true) {

        /* Check for any session parameter change below */

        /* Check for new detect_mult */
        if ((curr_params->detect_mult != curr_session->detect_mult) && curr_params->detect_mult > 0) {
            bfd_pr_debug(curr_params->log_file, "Change of detect_mult requested, new value: %d\n", curr_params->detect_mult);
            curr_session->detect_mult = curr_params->detect_mult;
        }

        /* Check for new DSCP value */
        if ((curr_params->dscp != curr_session->dscp) && curr_params->dscp > 0) {
            bfd_pr_debug(curr_params->log_file, "Change of DSCP value requested, new value: %d\n", curr_params->dscp);
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
                        bfd_pr_error(curr_params->log_file, "Can't build IP header: %s\n", libnet_geterror(l));
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
                    bfd_pr_error(curr_params->log_file, "Can't build IP header: %s\n", libnet_geterror(l));
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

                /* Reset state variables */
                bfd_reset_session_state_vars(curr_session);

                if (curr_params->callback != NULL) {
                    callback_status.cb_ret = BFD_CB_DETECT_TIME_EXPIRED;
                    curr_params->callback(&callback_status);
                }
            }
        }

        /* We have some data, get it and process it */
        if (ret > 0) {

            /* If TTL/Hop limit is not 255, packet MUST be discarded (section 5 in RFC5881) */
            if (get_ttl_or_hopl(&recv_hdr, curr_params->is_ipv6) != 255) {
                bfd_pr_debug(curr_params->log_file, "Wrong TTL value for received packet.\n");
                continue;
            }

            /* Rules for reception of BFD control packets (section 6.8.6 in RFC5880) */
            bfdp = (struct bfd_ctrl_packet *)recv_buf;

            /* If the version number is not correct (1), packet MUST be discarded */
            if (((bfdp->byte1.version >> 5) & 0x07) != 1) {
                bfd_pr_debug(curr_params->log_file, "Wrong protocol version number.\n");
                continue;
            }

            /* If the Length field is not correct, packet MUST be discarded */
            if (bfdp->length != BFD_PKG_MIN_SIZE) {
                bfd_pr_debug(curr_params->log_file, "Wrong packet length.\n");
                continue;
            }

            /* If the Detect Mult field <= 0, packet MUST be discarded */
            if (bfdp->detect_mult <= 0) {
                bfd_pr_debug(curr_params->log_file, "Wrong detect mult.\n");
                continue;
            }

            /* If the Multipoint bit is != 0, packet MUST be discarded */
            if ((bfdp->byte2.multipoint & 0x01) != 0) {
                bfd_pr_debug(curr_params->log_file, "Wrong multipoint setting.\n");
                continue;
            }

            /* If My Discr <= 0, packet MUST be discarded */
            if (ntohl(bfdp->my_discr) <= 0) {
                bfd_pr_debug(curr_params->log_file, "Bad my_discr value.\n");
                continue;
            }

            /* If Your Discr <= zero and State is not Down or AdminDown, packet MUST be discarded */
            if (ntohl(bfdp->your_discr) <= 0 && ((((bfdp->byte2.state >> 6) & 0x03) != BFD_STATE_DOWN) ||
                    (((bfdp->byte2.state >> 6) & 0x03) == BFD_STATE_ADMIN_DOWN))) {
                bfd_pr_debug(curr_params->log_file, "Bad state, zero your_discr.\n");
                continue;
            }

            /* If A bit is set, packet MUST be discarded (we don't support authentication) */
            if (((bfdp->byte2.auth_present >> 2) & 0x01) == true) {
                bfd_pr_debug(curr_params->log_file, "Authentication is not supported, discarding packet.\n");
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
                bfd_pr_debug(curr_params->log_file, "Finishing poll Sequence with remote: %s\n", curr_params->dst_ip);
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

            if (curr_session->remote_poll_in_progress)
                curr_session->local_final = false;

            /* BFD state machine logic */
            if (curr_session->local_state == BFD_STATE_ADMIN_DOWN) {
                continue;
            }

            if (curr_session->remote_state == BFD_STATE_ADMIN_DOWN) {
                if (curr_session->local_state != BFD_STATE_DOWN) {
                    curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                    curr_session->local_state = BFD_STATE_DOWN;
                    if (curr_params->callback != NULL) {
                        callback_status.cb_ret = BFD_CB_REMOTE_SIGN_ADMIN_DOWN;
                        curr_params->callback(&callback_status);
                    }
                }
            }
            else {
                if (curr_session->local_state == BFD_STATE_DOWN) {
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                        curr_session->local_state = BFD_STATE_INIT;

                        /* Reset detection time */
                        if (curr_session->detection_time < 1250000)
                            curr_session->detection_time = 1250000;

                        if (curr_params->callback != NULL) {
                            callback_status.cb_ret = BFD_CB_SESSION_INIT;
                            curr_params->callback(&callback_status);
                        }
                    }
                    else if (curr_session->remote_state == BFD_STATE_INIT) {
                        curr_session->local_state = BFD_STATE_UP;
                        curr_session->local_diag = BFD_DIAG_NODIAG;  // should this be updated?
                        if (curr_params->callback != NULL) {
                            callback_status.cb_ret = BFD_CB_SESSION_UP;
                            curr_params->callback(&callback_status);
                        }
                    }
                }
                else if (curr_session->local_state == BFD_STATE_INIT) {
                        if (curr_session->remote_state == BFD_STATE_INIT || curr_session->remote_state == BFD_STATE_UP) {
                            curr_session->local_state = BFD_STATE_UP;
                            curr_session->local_diag = BFD_DIAG_NODIAG; // should this be updated?
                            if (curr_params->callback != NULL) {
                                callback_status.cb_ret = BFD_CB_SESSION_UP;
                                curr_params->callback(&callback_status);
                            }
                        } else {
                            /* Reset detection time */
                            if (curr_session->detection_time < 1250000)
                                curr_session->detection_time = 1250000;
                        }
                    }
                else {   //curr_session->local_state = BFD_STATE_UP
                    if (curr_session->remote_state == BFD_STATE_DOWN) {
                        curr_session->local_diag = BFD_DIAG_NEIGH_SIGNL_SESS_DOWN;
                        curr_session->local_state = BFD_STATE_DOWN;

                        /* Reset state variables */
                        bfd_reset_session_state_vars(curr_session);

                        if (curr_params->callback != NULL) {
                                callback_status.cb_ret = BFD_CB_REMOTE_SIGN_DOWN;
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
                
                curr_session->remote_poll_in_progress = true;
                curr_session->local_poll = false;
                curr_session->local_final = true;

                /* Update packet data */
                bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
                    curr_session->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
                    curr_session->req_min_rx_interval, &pkt);

                /* Update UDP header */
                bfd_build_udp(&pkt, curr_session->src_port, &udp_tag, l);

                /* Send BFD packet on wire */
                if (libnet_write(l) == -1) {
                    bfd_pr_error(curr_params->log_file, "Write error: %s\n", libnet_geterror(l));
                    continue;
                }
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
        bfd_pr_error(NULL, "bfd_session_create for IP: %s failed, err: %d\n", params->src_ip, ret);
        return -1;
    }

    sem_wait(&new_thread.s_id_sem);

    /* Copy the session id */
    new_thread.current_session->session_id = session_id;
    new_thread.current_session->curr_sess_cb_status->session_id = session_id;

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
        pthread_rwlock_wrlock(&write_lock);
        bfd_remove_session_from_list(&head, session_id);
        pthread_rwlock_unlock(&write_lock);

        bfd_pr_debug(NULL, "Stopping BFD session: %ld\n", session_id);
        pthread_cancel(session_id);
        pthread_join(session_id, NULL);
    }
}

static void tx_timeout_handler(union sigval sv)
{
    struct bfd_session *curr_session = sv.sival_ptr;

    uint32_t jitt_maxpercent;
    uint32_t tx_jitter;
    struct bfd_ctrl_packet *pkt = curr_session->pkt;
    libnet_ptag_t *udp_tag = curr_session->udp_tag;
    libnet_t *l = curr_session->l;
    struct itimerspec *tx_ts = curr_session->session_timer->tx_ts;

    if (curr_session->poll_in_progress == true)
        curr_session->local_poll = true;

    /* Update packet data */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
        curr_session->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
        curr_session->req_min_rx_interval, pkt);

    /* Update UDP header */
    bfd_build_udp(pkt, curr_session->src_port, udp_tag, l);

    /* Send BFD packet on wire */
    if (libnet_write(l) == -1) {
        bfd_pr_error(NULL, "Write error: %s\n", libnet_geterror(l));
        pthread_exit(NULL);
    }

    /* Apply jitter to TX transmit interval as per section 6.8.7 and start the timer for the next packet */
    jitt_maxpercent = (curr_session->detect_mult == 1) ? 15 : 25;
    tx_jitter = (curr_session->op_tx * (75 + ((uint32_t) random() % jitt_maxpercent))) / 100;
    bfd_update_timer(tx_jitter, tx_ts, curr_session->session_timer);
}

static void thread_cleanup(void *args)
{
    struct bfd_session *curr_session = (struct bfd_session *)args;
    struct bfd_timer *session_timer = curr_session->session_timer;

    /* Clean up TX timer */
    if (session_timer->is_created == true) {
        timer_delete(session_timer->timer_id);
        /*
         * Temporary workaround for C++ programs, seems sometimes the timer doesn't
         * get disarmed in time, and tries to use memory that was already freed.
         */
        usleep(100000);
    }

    /* Clean up libnet context */
    if (curr_session->l != NULL)
        libnet_destroy(curr_session->l);

    /* Cleanup socket */
    if (curr_session->sockfd != 0)
        close(curr_session->sockfd);

    /*
     * If a session is not successfully configured, we don't call pthread_join on it,
     * only exit using pthread_exit. Calling pthread_detach here should automatically
     * release resources for unconfigured sessions.
     */
    if (curr_session->is_configured == false)
        pthread_detach(pthread_self());
}

/* Reset state variables when a session goes DOWN */
static void bfd_reset_session_state_vars(struct bfd_session *session)
{
    /* Reset the operational TX to min 1s rate */
    if (session->op_tx < 1000000)
        session->op_tx = 1000000;

    /* Clear remote discriminator value */
    session->remote_discr = 0;

    /* Reset RemoteMinRxInterval (Section 6.8.18 in RFC5880)*/
    session->remote_min_rx_interval = 1;

    /* Reset detection time to min 1s */
    if (session->detection_time < 1250000)
        session->detection_time = 1250000;
}

static void bfd_add_session_to_list(struct bfd_session_node **head_ref, struct bfd_session_node *new_node)
{
    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}

static void bfd_remove_session_from_list(struct bfd_session_node **head_ref, bfd_session_id session_id)
{
    struct bfd_session_node *it = *head_ref, *prev = NULL;

    if (it != NULL && it->current_session->session_id == session_id) {
        *head_ref = it->next;
        return;
    }

    while (it != NULL && it->current_session->session_id != session_id) {
        prev = it;
        it = it->next;
    }

    if (it == NULL)
        return;

    prev->next = it->next;
}

static int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *timer_data)
{
    /* Update timer interval */
    ts->it_interval.tv_sec = interval_us / 1000000;
    ts->it_interval.tv_nsec = interval_us % 1000000 * 1000;
    ts->it_value.tv_sec = interval_us / 1000000;
    ts->it_value.tv_nsec = interval_us % 1000000 * 1000;

    if (timer_settime(timer_data->timer_id, 0, ts, NULL) == -1) {
        bfd_pr_error(NULL, "Cannot update timer.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static bool is_ip_valid(char *ip, bool is_ipv6)
{
    if (is_ipv6 == true) {
        struct sockaddr_in6 sa;

        int ret = inet_pton(AF_INET6, ip, &(sa.sin6_addr));

        if (ret == 1)
            return true;
        else if (ret == 0)
            return false;
    }
    else {
        struct sockaddr_in sa;

        int ret = inet_pton(AF_INET, ip, &(sa.sin_addr));

        if (ret == 1)
            return true;
        else if (ret == 0)
            return false;
    }

    return false;
}

static int get_ttl_or_hopl(struct msghdr *recv_msg, bool is_ipv6)
{
    int ttl_hopl = -1;

    if (is_ipv6 == true) {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(recv_msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
                uint8_t *hopl_ptr = (uint8_t *)CMSG_DATA(cmsg);
                ttl_hopl = *hopl_ptr;
                break;
            }
        }
    } else {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(recv_msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
                uint8_t *ttl_ptr = (uint8_t *)CMSG_DATA(cmsg);
                ttl_hopl = *ttl_ptr;
                break;
            }
        }
    }

    return ttl_hopl;
}

/* 
 * Check if provided IP address is assigned and if the interface using it is up.
 * If IP is found, name of interface is copied in buffer pointed by 3rd argument.
 * 
 * Return:
 *     -1   - IP is not assigned on any interface
 *      0   - IP is assigned and the interface is up
 *      1   - IP is assigned but the interface is down
 */
static int is_ip_live(char *ip_addr, bool is_ipv6, char *if_name)
{
    struct ifaddrs *addrs, *ifp;

    /* Get a list of network interfaces on the system */
    if (getifaddrs(&addrs) == -1) {
        bfd_pr_error(NULL, "Cannot get list of network interfaces.\n");
        return false;
    }

    /* Walk through the list and find the interface that uses our IP */
    ifp = addrs;

    while (ifp != NULL) {
        if (is_ipv6 == true) {
            if (ifp->ifa_addr && ifp->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ifp->ifa_addr;
                char conv_ip[INET6_ADDRSTRLEN];

                inet_ntop(AF_INET6, &(sa->sin6_addr), conv_ip, INET6_ADDRSTRLEN);

                if (strcmp(ip_addr, conv_ip) == 0) {
                    /* We found the interface, copy the name */
                    if (if_name != NULL)
                        strcpy(if_name, ifp->ifa_name);
                    /* Is the interface up? */
                    if (ifp->ifa_flags & IFF_UP) {
                        freeifaddrs(addrs);
                        return 0;
                    } else {
                        freeifaddrs(addrs);
                        return 1;
                    }
                }
            }
        } else {
            if (ifp->ifa_addr && ifp->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifp->ifa_addr;
                char conv_ip[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &(sa->sin_addr), conv_ip, INET_ADDRSTRLEN);

                if (strcmp(ip_addr, conv_ip) == 0) {
                    /* We found the interface, copy the name */
                    if (if_name != NULL)
                        strcpy(if_name, ifp->ifa_name);
                    /* Is the interface up? */
                    if (ifp->ifa_flags & IFF_UP) {
                        freeifaddrs(addrs);
                        return 0;
                    } else {
                        freeifaddrs(addrs);
                        return 1;
                    }
                }
            }
        }
        ifp = ifp->ifa_next;
    }

    /* No interface with the provided IP found */
    freeifaddrs(addrs);

    return -1;
}