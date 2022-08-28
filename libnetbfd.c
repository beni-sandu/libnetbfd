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

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <libnet.h>

#include "libnetbfd.h"
#include "bfd_packet.h"
#include "bfd_session.h"

/* Globals */
struct bfd_session_node *head = NULL;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

void bfd_session_change_param(bfd_session_id session_id, enum bfd_param param, uint32_t new_value)
{
    /* Find the session that we're interested in */
    pthread_rwlock_wrlock(&rwlock);
    struct bfd_session_node *session = bfd_find_session(session_id);

    if (session == NULL) {
        fprintf(stderr, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    switch (param) {

        case PARAM_DSCP:

            session->session_params->dscp = new_value;
            pthread_rwlock_unlock(&rwlock);

            break;

        case PARAM_DETECT_MULT:

            session->session_params->detect_mult = new_value;
            pthread_rwlock_unlock(&rwlock);

            break;

        default:
            fprintf(stderr, "Invalid bfd_session_change_param command.\n");
            pthread_rwlock_unlock(&rwlock);
            break;
    }
}

void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval)
{
    pthread_rwlock_wrlock(&rwlock);
    struct bfd_session_node *session = bfd_find_session(session_id);

    if (session == NULL) {
        fprintf(stderr, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    switch (cmd) {
        case SESSION_ENABLE_ADMIN_DOWN:

            if (session->session_params->current_session->local_state != BFD_STATE_ADMIN_DOWN) {
                pr_debug("Putting session: %ld into ADMIN_DOWN.\n", session_id);
                session->session_params->current_session->local_state = BFD_STATE_ADMIN_DOWN;
                session->session_params->current_session->local_diag = BFD_DIAG_ADMIN_DOWN;
            }
            else
                fprintf(stderr, "Session: %ld is already in ADMIN_DOWN, skipping.\n", session_id);
            pthread_rwlock_unlock(&rwlock);

            break;

        case SESSION_DISABLE_ADMIN_DOWN:

            if (session->session_params->current_session->local_state == BFD_STATE_ADMIN_DOWN) {
                pr_debug("Getting session: %ld out of ADMIN_DOWN.\n", session_id);
                session->session_params->current_session->local_state = BFD_STATE_DOWN;
                session->session_params->current_session->local_diag = BFD_DIAG_NODIAG;
            }
            else
                fprintf(stderr, "Session: %ld was not in ADMIN_DOWN, skipping.\n", session_id);
            pthread_rwlock_unlock(&rwlock);

            break;

        case SESSION_CHANGE_BFD_INTERVALS:

            if (des_min_tx_interval == 0 && req_min_rx_interval == 0) {
                fprintf(stderr, "Both parameters are 0, nothing to be done.\n");
                pthread_rwlock_unlock(&rwlock);
                return;
            }

            pr_debug("BFD interval change requested for session [%s <--> %s], initiating Poll Sequence.\n", session->session_params->src_ip, session->session_params->dst_ip);

            /* Is it a good idea to change both of them at the same time? Time(testing) will tell */
            if (des_min_tx_interval > 0)
                session->session_params->des_min_tx_interval = des_min_tx_interval;

            if (req_min_rx_interval > 0)
                session->session_params->req_min_rx_interval = req_min_rx_interval;

            session->session_params->current_session->poll_in_progress = true;
            pthread_rwlock_unlock(&rwlock);

            break;

        default:
            fprintf(stderr, "Invalid bfd_session_modify command.\n");
            pthread_rwlock_unlock(&rwlock);
            break;
    }
}

int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *timer_data)
{
    /* Update timer interval */
    ts->it_interval.tv_sec = interval_us / 1000000;
    ts->it_interval.tv_nsec = interval_us % 1000000 * 1000;
    ts->it_value.tv_sec = interval_us / 1000000;
    ts->it_value.tv_nsec = interval_us % 1000000 * 1000;

    if (timer_settime(timer_data->timer_id, 0, ts, 0) == -1) {
        perror("timer settime");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

const char *state2string(enum bfd_state state)
{
    switch(state) {
        case BFD_STATE_UP:
            return "BFD_STATE_UP";
        case BFD_STATE_DOWN:
            return "BFD_STATE_DOWN";
        case BFD_STATE_INIT:
            return "BFD_STATE_INIT";
        case BFD_STATE_ADMIN_DOWN:
            return "BFD_STATE_ADMIN_DOWN";
    }

    return "UNKNOWN BFD STATE";
}

bool is_ip_valid(char *ip, bool is_ipv6)
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

void bfd_add_session(struct bfd_session_node **head_ref, struct bfd_session_node *new_node)
{
    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}

void bfd_remove_session(struct bfd_session_node **head_ref, bfd_session_id session_id)
{
    struct bfd_session_node *it = *head_ref, *prev = NULL;

    if (it != NULL && it->session_params->current_session->session_id == session_id) {
        *head_ref = it->next;
        return;
    }

    while (it != NULL && it->session_params->current_session->session_id != session_id) {
        prev = it;
        it = it->next;
    }

    if (it == NULL)
        return;

    prev->next = it->next;
}

struct bfd_session_node *bfd_find_session(bfd_session_id session_id)
{
    struct bfd_session_node *it = head;

    while (it != NULL) {
        if (it->session_params->current_session->session_id == session_id)
            return it;
        it = it->next;
    }

    return NULL;
}

void bfd_session_print_stats(bfd_session_id session_id)
{
    time_t now;
    struct tm *local = NULL;
    char timestamp[100];

    pthread_rwlock_rdlock(&rwlock);
    struct bfd_session_node *session = bfd_find_session(session_id);

    if (session == NULL) {
        fprintf(stderr, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    /* Get and format timestamp */
    now = time(NULL);
    local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%d-%b-%Y %H:%M:%S", local);

    printf("---------------------------------------------\n");
    printf("%-25s %s\n", "Timestamp:", timestamp);
    printf("%-25s %ld\n", "Session ID:", session->session_params->current_session->session_id);
    if (strlen(session->session_params->net_ns))
        printf("%-25s %s\n", "Network namespace:", session->session_params->net_ns);
    printf("%-25s %s\n", "Source IP:", session->session_params->src_ip);
    printf("%-25s %s\n", "Destination IP:", session->session_params->dst_ip);
    printf("%-25s %d\n", "Source port:", session->session_params->current_session->src_port);
    printf("%-25s %d\n", "Destination port:", session->session_params->current_session->dst_port);
    printf("%-25s %s\n", "Device:", session->session_params->current_session->if_name);
    printf("%-25s %d\n", "DSCP:", session->session_params->dscp);
    printf("%-25s %d\n", "Des min TX interval:", session->session_params->current_session->des_min_tx_interval);
    printf("%-25s %d\n", "Req min RX interval:", session->session_params->current_session->req_min_rx_interval);
    printf("%-25s %d\n", "Detection Multiplier:", session->session_params->detect_mult);
    printf("%-25s 0x%x\n", "My discriminator:", session->session_params->current_session->local_discr);
    printf("%-25s %s\n", "Current state:", state2string(session->session_params->current_session->local_state));
    printf("%-25s %d\n", "Operational TX:", session->session_params->current_session->op_tx);
    printf("%-25s %d\n", "Detection time:", session->session_params->current_session->detection_time);
    printf("---------------------------------------------\n");

    pthread_rwlock_unlock(&rwlock);
}

void bfd_session_print_stats_log(bfd_session_id session_id)
{
    time_t now;
    struct tm *local = NULL;
    char timestamp[100];
    FILE *file = NULL;

    pthread_rwlock_rdlock(&rwlock);
    struct bfd_session_node *session = bfd_find_session(session_id);

    if (session == NULL) {
        fprintf(stderr, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    /* Open log file */
    if (strlen(session->session_params->log_file) == 0) {
        pthread_rwlock_unlock(&rwlock);
        return;
    } else {
        file = fopen(session->session_params->log_file, "a");

        if (file == NULL) {
            perror("fopen");
            pthread_rwlock_unlock(&rwlock);
            return;
        }
    }

    /* Get and format timestamp */
    now = time(NULL);
    local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%d-%b-%Y %H:%M:%S", local);

    fprintf(file, "---------------------------------------------\n");
    fprintf(file, "%-25s %s\n", "Timestamp:", timestamp);
    fprintf(file, "%-25s %ld\n", "Session ID:", session->session_params->current_session->session_id);
    if (strlen(session->session_params->net_ns))
        fprintf(file, "%-25s %s\n", "Network namespace:", session->session_params->net_ns);
    fprintf(file, "%-25s %s\n", "Source IP:", session->session_params->src_ip);
    fprintf(file, "%-25s %s\n", "Destination IP:", session->session_params->dst_ip);
    fprintf(file, "%-25s %d\n", "Source port:", session->session_params->current_session->src_port);
    fprintf(file, "%-25s %d\n", "Destination port:", session->session_params->current_session->dst_port);
    fprintf(file, "%-25s %s\n", "Device:", session->session_params->current_session->if_name);
    fprintf(file, "%-25s %d\n", "DSCP:", session->session_params->dscp);
    fprintf(file, "%-25s %d\n", "Des min TX interval:", session->session_params->current_session->des_min_tx_interval);
    fprintf(file, "%-25s %d\n", "Req min RX interval:", session->session_params->current_session->req_min_rx_interval);
    fprintf(file, "%-25s %d\n", "Detection Multiplier:", session->session_params->detect_mult);
    fprintf(file, "%-25s 0x%x\n", "My discriminator:", session->session_params->current_session->local_discr);
    fprintf(file, "%-25s %s\n", "Current state:", state2string(session->session_params->current_session->local_state));
    fprintf(file, "%-25s %d\n", "Operational TX:", session->session_params->current_session->op_tx);
    fprintf(file, "%-25s %d\n", "Detection time:", session->session_params->current_session->detection_time);
    fprintf(file, "---------------------------------------------\n");
    fclose(file);

    pthread_rwlock_unlock(&rwlock);
}

/* Return library version */
const char *netbfd_lib_version(void)
{
    return ("libnetbfd version "LIBNETBFD_VERSION);
}

int get_ttl(struct msghdr *recv_msg)
{
    int ttl = -1;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(recv_msg, cmsg))
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
            uint8_t *ttl_ptr = (uint8_t *)CMSG_DATA(cmsg);
            ttl = *ttl_ptr;
            break;
        }

    return ttl;
}

void print_log(char *log_file, const char *format, ...)
{
    va_list arg;
    time_t now;
    struct tm *local = NULL;
    char timestamp[100];
    FILE *file = NULL;

    if (strlen(log_file) == 0)
        return;
    else {
        file = fopen(log_file, "a");

        if (file == NULL) {
            perror("fopen");
            return;
        }
    }

    va_start(arg, format);
    now = time(NULL);
    local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%d-%b-%Y %H:%M:%S", local);
    fprintf(file, "[%s] ", timestamp);
    vfprintf(file, format, arg);
    va_end(arg);
    fclose(file);
}

/*
 * Check if provided IP address is assigned on the local machine
 * and if it is, return true only if the interface that is using it
 * is UP. For any other scenario, return false.
 *
 * If we return true, also copy the interface name in buffer pointed
 * by 3rd argument.
 */
bool is_ip_live(char *ip_addr, bool is_ipv6, char *if_name)
{
    struct ifaddrs *addrs, *ifp;

    /* Get a list of network interfaces on the system */
    if (getifaddrs(&addrs) == -1) {
        perror("getifaddrs");
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

                    /* We found the interface, check if it's up */
                    if (ifp->ifa_flags & IFF_UP) {
                        pr_debug("Interface %s with IP %s is UP.\n", ifp->ifa_name, ip_addr);
                        if (if_name != NULL)
                            strcpy(if_name, ifp->ifa_name);
                        freeifaddrs(addrs);
                        return true;
                    } else {
                        pr_debug("Interface %s with IP %s is DOWN.\n", ifp->ifa_name, ip_addr);
                        freeifaddrs(addrs);
                        return false;
                    }
                }
            }
        } else {
            if (ifp->ifa_addr && ifp->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifp->ifa_addr;
                char conv_ip[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &(sa->sin_addr), conv_ip, INET_ADDRSTRLEN);

                if (strcmp(ip_addr, conv_ip) == 0) {

                    /* We found the interface, check if it's up */
                    if (ifp->ifa_flags & IFF_UP) {
                        pr_debug("Interface %s with IP %s is UP.\n", ifp->ifa_name, ip_addr);
                        if (if_name != NULL)
                            strcpy(if_name, ifp->ifa_name);
                        freeifaddrs(addrs);
                        return true;
                    } else {
                        pr_debug("Interface %s with IP %s is DOWN.\n", ifp->ifa_name, ip_addr);
                        freeifaddrs(addrs);
                        return false;
                    }
                }
            }
        }
        ifp = ifp->ifa_next;
    }

    /* No interface with the provided IP found */
    freeifaddrs(addrs);

    return false;
}
