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
__thread char recv_buf[BFD_PKG_MIN_SIZE];                    /* Buffer for received packet */
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

/* Forward declarations */
void tx_timeout_handler(union sigval sv);
void thread_cleanup(void *args);
int recvfrom_ppoll(int sockfd, char *recv_buf, int buf_size, int timeout_us);
void *bfd_session_run(void *args);

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

    /* Useful pointers */
    struct bfd_thread *current_thread = (struct bfd_thread *)args;
    struct bfd_session_params *curr_params = current_thread->session_params;
    struct bfd_session new_session;
    curr_params->current_session = &new_session;
    struct bfd_session *curr_session = curr_params->current_session;

    /* Initialize timer data */
    tx_timer.sess_params = curr_params;
    tx_timer.pkt = &pkt;
    tx_timer.udp_tag = &udp_tag;
    tx_timer.tx_ts = &tx_ts;
    tx_timer.timer_id = NULL;

    /*
     * Define some callback return codes here to cover cases that we're interested in (can be adjusted later if needed):
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
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

    /* Make sure source/destination IPs are different */
    if (strcmp(curr_params->src_ip, curr_params->dst_ip) == 0) {
        fprintf(stderr, "Cannot use same IP address for both source/destination.\n");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

    /* libnet init */
    if (curr_params->is_ipv6 == true) {
        l = libnet_init(
            LIBNET_RAW6,                                /* injection type */
            NULL,                                       /* network interface */
            libnet_errbuf);                             /* error buffer */

        if (l == NULL) {
            fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (is_ip_valid(curr_params->src_ip, true) == false) {
            fprintf(stderr, "Bad source IPv6 address: %s\n", curr_params->src_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        src_ipv6 = libnet_name2addr6(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);

        if (is_ip_valid(curr_params->dst_ip, true) == false) {
            fprintf(stderr, "Bad destination IPv6 address: %s\n", curr_params->dst_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        dst_ipv6 = libnet_name2addr6(l, curr_params->dst_ip, LIBNET_DONT_RESOLVE);
    }
    else {
        l = libnet_init(
            LIBNET_RAW4,                                /* injection type */
            NULL,                                       /* network interface */
            libnet_errbuf);                             /* error buffer */

        if (l == NULL) {
            fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }

        if (is_ip_valid(curr_params->src_ip, false) == false) {
            fprintf(stderr, "Bad source IPv4 address: %s\n", curr_params->src_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
        src_ipv4 = libnet_name2addr4(l, curr_params->src_ip, LIBNET_DONT_RESOLVE);

        if (is_ip_valid(curr_params->dst_ip, false) == false) {
            fprintf(stderr, "Bad destination IPv4 address: %s\n", curr_params->dst_ip);
            current_thread->ret = -1;
            sem_post(&current_thread->sem);
            pthread_exit(NULL);
        }
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
    curr_session->remote_min_rx_interval = 0;
    curr_session->remote_state = BFD_STATE_DOWN;
    curr_session->detection_time = 1000000;
    curr_session->local_poll = false;
    curr_session->local_final = false;
    curr_session->poll_in_progress = false;
    curr_session->final_detection_time = 0;
    curr_session->final_op_tx = 0;

    /* Get a source port for the session */
    pthread_mutex_lock(&port_lock);
    curr_session->src_port = src_port++;
    pthread_mutex_unlock(&port_lock);

    /* Build initial BFD control packet */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
                curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
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
            (curr_params->dscp << 2) & 0xFC,                    /* DSCP */
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
            (curr_params->dscp << 2) & 0xFC,                    /* DSCP */
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
    if (timer_create(CLOCK_REALTIME, &tx_sev, &tx_timer.timer_id) == -1) {
        perror("timer_create");
        current_thread->ret = -1;
        sem_post(&current_thread->sem);
        pthread_exit(NULL);
    }

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

    /* Copy params pointer to session node */
    session_node.session_params = curr_params;

    /* Add the session to the list */
    pthread_rwlock_wrlock(&rwlock);
    bfd_add_session(&head, &session_node);
    pthread_rwlock_unlock(&rwlock);

    /* Session configuration is successful, return a valid session id */
    sem_post(&current_thread->sem);

    /* Start sending packets at Desired min TX interval */
    bfd_update_timer(curr_session->op_tx, &tx_ts, &tx_timer);

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
                if (curr_params->callback != NULL) {
                    callback_status.cb_ret = 1;
                    curr_params->callback(&callback_status);
                }
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
                        if (curr_params->callback != NULL) {
                            callback_status.cb_ret = 3;
                            curr_params->callback(&callback_status);
                        }
                    }
                }
                else if (curr_session->local_state == BFD_STATE_INIT) {
                        if (curr_session->remote_state == BFD_STATE_INIT || curr_session->remote_state == BFD_STATE_UP) {
                            curr_session->local_state = BFD_STATE_UP;
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
                    curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
                    curr_session->req_min_rx_interval, &pkt);

                /* Update UDP header */
                bfd_build_udp(&pkt, curr_session->src_port, &udp_tag, l);

                /* Send BFD packet on wire */
                c = libnet_write(l);

                /* We only send 1 packet with the Final (F) bit set, so flip it back */
                curr_session->local_final = false;

                if (c == -1) {
                    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
                    pthread_exit(NULL);
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
bfd_session_id bfd_session_start(struct bfd_session_params *params) {
    
    pthread_t session_id;
    int ret;
    struct bfd_thread new_thread;

    new_thread.session_params = params;
    new_thread.ret = 0;

    sem_init(&new_thread.sem, 0, 0);

    ret = pthread_create(&session_id, NULL, bfd_session_run, (void *)&new_thread);

    if (ret) {
        fprintf(stderr, "bfd_session_create for IP: %s failed, err: %d\n", params->src_ip, ret);
        return -1;
    }

    sem_wait(&new_thread.sem);

    if (new_thread.ret != 0)
        return new_thread.ret;

    /* Copy the session id */
    params->current_session->session_id = session_id;
    
    return session_id;
}

/* Stop a BFD session */
void bfd_session_stop(bfd_session_id session_id) {

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

    if (curr_session->poll_in_progress == true)
        curr_session->local_poll = true;

    /* Update packet data */
    bfd_build_packet(curr_session->local_diag, curr_session->local_state, curr_session->local_poll, curr_session->local_final,
        curr_params->detect_mult, curr_session->local_discr, curr_session->remote_discr, curr_session->des_min_tx_interval,
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
    jitt_maxpercent = (curr_params->detect_mult == 1) ? 15 : 25;
    tx_jitter = (curr_session->op_tx * (75 + ((uint32_t) random() % jitt_maxpercent))) / 100;
    bfd_update_timer(tx_jitter, tx_ts, timer_data);
}

void thread_cleanup(void *args) {
    
    struct bfd_timer *timer = (struct bfd_timer *)args;

    /* Cleanup allocated data */
    if (timer->timer_id != NULL)
        timer_delete(timer->timer_id);
    
    if (timer->l != NULL)
        libnet_destroy(timer->l);

    if (timer->sess_params->current_session->sockfd != 0)
        close(timer->sess_params->current_session->sockfd);
}