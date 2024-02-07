/*
 * Copyright: Beniamin Sandu <beniaminsandu@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LIBNETBFD_H
#define _LIBNETBFD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libnet.h>
#include <semaphore.h>
#include <pthread.h>

#include "bfd_packet.h"

/* Library version */
#define LIBNETBFD_VERSION "0.3"

/* Print macros */
#ifdef DEBUG_ENABLE
#define bfd_pr_debug(file, ...) \
    ( {printf("[DEBUG] "__VA_ARGS__) ; bfd_pr_log(file, "[DEBUG] "__VA_ARGS__);} )
#else
#define bfd_pr_debug(...) \
    ( {do {} while(0);} )
#endif

#define bfd_pr_info(file, ...) \
    ( {printf("[INFO] "__VA_ARGS__) ; bfd_pr_log(file, "[INFO] "__VA_ARGS__);} )

#define bfd_pr_error(file, ...) \
    ( {fprintf(stderr, "[ERROR] "__VA_ARGS__) ; bfd_pr_log(file, "[ERROR] "__VA_ARGS__);})

struct bfd_session_node {
    struct bfd_session *current_session;
    struct bfd_session_params *session_params;
    struct bfd_session_node *next;
};

struct bfd_thread {
    sem_t sem;
    sem_t s_id_sem;
    struct bfd_session_params *session_params;
    struct bfd_session *current_session;
    int ret;
};

enum bfd_modify_cmd {
    SESSION_ENABLE_ADMIN_DOWN       = 0,
    SESSION_DISABLE_ADMIN_DOWN      = 1,
    SESSION_CHANGE_BFD_INTERVALS    = 2,
};

enum bfd_param {
    PARAM_DSCP                      = 0,
    PARAM_DETECT_MULT               = 1,
};

/* Data passed to per thread timer */
struct bfd_timer {
    bool is_created;
    timer_t timer_id;                                       /* POSIX interval timer id */
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
const char *bfd_state2string(enum bfd_state state);
const char *bfd_diag2string(enum bfd_diag diag);
void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval);
void bfd_session_print_stats(bfd_session_id session_id);
void bfd_session_print_stats_log(bfd_session_id session_id);
const char *netbfd_lib_version(void);
void bfd_pr_log(char *log_file, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));
void bfd_session_change_param(bfd_session_id session_id, enum bfd_param param, uint32_t new_value);
int bfd_session_get_local_diag(bfd_session_id session_id);
int bfd_session_get_local_state(bfd_session_id session_id);

#ifdef __cplusplus
}
#endif

#endif // _LIBNETBFD_H
