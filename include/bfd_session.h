/*
 * Copyright: Beniamin Sandu <beniaminsandu@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BFD_SESSION_H
#define _BFD_SESSION_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <libnet.h>

/* RFC5881 (https://datatracker.ietf.org/doc/html/rfc5881) specifies the ports that MUST be used */
#define BFD_CTRL_PORT   3784

/* Any chance we get 16384 active BFD sessions? :) */
#define BFD_SRC_PORT_MIN    49152
#define BFD_SRC_PORT_MAX    65535

#define NET_NS_SIZE 32
#define MAX_PATH 512

/* Add a typedef for a BFD session ID */
typedef long int bfd_session_id;

enum bfd_diag {
    BFD_DIAG_NODIAG                     = 0,
    BFD_DIAG_CTRL_DETECT_TIME_EXPIRED   = 1,
    BFD_DIAG_ECHO_FUNCT_FAIL            = 2,
    BFD_DIAG_NEIGH_SIGNL_SESS_DOWN      = 3,
    BFD_DIAG_FWD_PLANE_RESET            = 4,
    BFD_DIAG_PATH_DOWN                  = 5,
    BFD_DIAG_CONCAT_PATH_DOWN           = 6,
    BFD_DIAG_ADMIN_DOWN                 = 7,
    BFD_DIAG_REV_CONCAT_PATH_DOWN       = 8,
};

enum bfd_state {
    BFD_STATE_ADMIN_DOWN                = 0,
    BFD_STATE_DOWN                      = 1,
    BFD_STATE_INIT                      = 2,
    BFD_STATE_UP                        = 3,
};

enum bfd_callback_ret {
    BFD_CB_DEFAULT                      = 0,
    BFD_CB_DETECT_TIME_EXPIRED          = 1,
    BFD_CB_SESSION_INIT                 = 2,
    BFD_CB_SESSION_UP                   = 3,
    BFD_CB_REMOTE_SIGN_DOWN             = 4,
    BFD_CB_REMOTE_SIGN_ADMIN_DOWN       = 5,
    BFD_CB_INTERFACE_DOWN               = 6,
    BFD_CB_SESSION_ENABLE_ADMIN_DOWN    = 7,
    BFD_CB_SESSION_DISABLE_ADMIN_DOWN   = 8,
    BFD_CB_SRC_IP_NOT_ASSIGNED          = 9,
};

struct cb_status {
    int cb_ret;                                             /* Callback return value */
    struct bfd_session_params *session_params;              /* Pointer to current session parameters */
    void *client_data;                                      /* Client specific data */
    bfd_session_id session_id;                              /* Current session id */
};

/* Parameters for a new BFD session */
struct bfd_session_params {
    char src_ip[INET6_ADDRSTRLEN];                          /* Source IP in string format (IPv4/IPv6) */
    char dst_ip[INET6_ADDRSTRLEN];                          /* Destination IP in string format (IPv4/IPv6) */
    bool is_ipv6;                                           /* Flag to select type of IP session */
    uint32_t des_min_tx_interval;                           /* Desired min TX interval for current session, BFD specific */
    uint32_t req_min_rx_interval;                           /* Required min RX interval for current session, BFD specific */
    uint8_t detect_mult;                                    /* Detection multiplier for current session, BFD specific */
    void (*callback)(struct cb_status *status);             /* Session callback */
    uint8_t dscp;                                           /* IP differentiated services code point */
    char net_ns[NET_NS_SIZE];                               /* Network namespace name */
    uint16_t src_port;                                      /* Source port */
    char log_file[MAX_PATH];                                /* Path to log file */
    void *client_data;                                      /* Client specific data */
};

/*
 * Structure to describe a BFD session with all the state variables
 */
struct bfd_session {
    uint8_t remote_version;
    bool remote_multipoint;
    bool remote_auth;
    enum bfd_state local_state;
    enum bfd_state remote_state;
    uint32_t local_discr;
    uint32_t remote_discr;
    enum bfd_diag local_diag;
    enum bfd_diag remote_diag;
    uint32_t des_min_tx_interval;
    uint32_t remote_des_min_tx_interval;
    uint32_t req_min_rx_interval;
    uint32_t remote_min_rx_interval;
    uint64_t detection_time;
    uint8_t remote_detect_mult;
    uint32_t op_tx;
    uint32_t final_op_tx;
    uint64_t final_detection_time;
    bool local_poll;
    bool local_final;
    bool remote_poll;
    bool remote_final;
    bool poll_in_progress;
    bool remote_poll_in_progress;
    int sockfd;
    uint16_t src_port;
    uint16_t dst_port;
    bfd_session_id session_id;
    uint8_t dscp;
    uint8_t detect_mult;
    char *if_name;
    struct cb_status *curr_sess_cb_status;
    int prev_bfd_diag;
    struct bfd_timer *session_timer;
    bool is_configured;
    struct bfd_ctrl_packet *pkt;
    libnet_ptag_t *udp_tag;
    libnet_t *l;
};

/* Function prototypes */
bfd_session_id bfd_session_start(struct bfd_session_params *params);
void bfd_session_stop(bfd_session_id session_id);

#endif // _BFD_SESSION_H
