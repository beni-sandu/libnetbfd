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

#ifndef LIBNETBFD_H
#define LIBNETBFD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libnet.h>
#include <semaphore.h>
#include <pthread.h>

#include "bfd_packet.h"

/* Library version */
#define LIBNETBFD_VERSION "0.1"

#ifdef DEBUG_ENABLE
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug(...)
#endif

struct bfd_session_node {
    struct bfd_session_params *session_params;
    struct bfd_session_node *next;
};

struct bfd_thread {
    sem_t sem;
    struct bfd_session_params *session_params;
    int ret;
};

enum bfd_modify_cmd {
    SESSION_ENABLE_ADMIN_DOWN       = 0,
    SESSION_DISABLE_ADMIN_DOWN      = 1,
    SESSION_CHANGE_PARAMS           = 2
};

/* Data passed to per thread timer */
struct bfd_timer {
    bool is_timer_created;
    bool is_session_configured;
    timer_t timer_id;                                       /* POSIX interval timer id */
    struct bfd_session_params *sess_params;                 /* pointer to current BFD session parameters if needed */
    struct bfd_ctrl_packet *pkt;
    libnet_ptag_t *udp_tag;
    libnet_t *l;
    struct itimerspec *tx_ts;
};

/* Wrapper to update UDP header */
static inline void bfd_build_udp(struct bfd_ctrl_packet *pkt, uint16_t src_port, libnet_ptag_t *udp_tag, libnet_t *l) {
    
    *udp_tag = libnet_build_udp(
        src_port,                                           /* Source port */
        BFD_CTRL_PORT,                                      /* Destination port */
        LIBNET_UDP_H + BFD_PKG_MIN_SIZE,                    /* Packet lenght */
        0,                                                  /* Checksum */
        (uint8_t *)pkt,                                     /* Payload */
        BFD_PKG_MIN_SIZE,                                   /* Payload size */
        l,                                                  /* libnet handle */
        *udp_tag);                                          /* libnet tag */

    if (*udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        pthread_exit(NULL);
    }
}

/* Function prototypes */
int bfd_start_tx_timer(struct bfd_timer *timer_data, struct itimerspec *ts);
int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *btimer);
const char *state2string(enum bfd_state state);
void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval);
bool is_ip_valid(char *ip, bool is_ipv6);
void bfd_add_session(struct bfd_session_node **head, struct bfd_session_node *new_node);
struct bfd_session_node *bfd_find_session(bfd_session_id session_id);
void bfd_session_print_stats(bfd_session_id session_id);
void bfd_session_print_stats_log(bfd_session_id session_id);
void bfd_remove_session(struct bfd_session_node **head_ref, bfd_session_id session_id);
const char *netbfd_lib_version(void);
int get_ttl(struct msghdr *recv_msg);
void print_log(char *log_file, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));

#ifdef __cplusplus
}
#endif

#endif //LIBNETBFD_H