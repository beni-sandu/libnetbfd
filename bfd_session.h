#ifndef BFD_SESSION_H_
#define BFD_SESSION_H_

#include <stdbool.h>

/* RFC5881 (https://datatracker.ietf.org/doc/html/rfc5881) specifies the ports that MUST be used */
#define BFD_CTRL_PORT   3784

/* Any chance we get 16384 active BFD sessions? :) */
#define BFD_SRC_PORT_MIN    49152
#define BFD_SRC_PORT_MAX    65535

enum bfd_diag {
    BFD_DIAG_NODIAG                     = 0,
    BFD_DIAG_CTRL_DETECT_TIME_EXPIRED   = 1,
    BFD_DIAG_ECHO_FUNCT_FAIL            = 2,
    BFD_DIAG_NEIGH_SIGNL_SESS_DOWN      = 3,
    BFD_DIAG_FWD_PLANE_RESET            = 4,
    BFD_DIAG_PATH_DOWN                  = 5,
    BFD_DIAG_CONCAT_PATH_DOWN           = 6,
    BFD_DIAG_ADMIN_DOWN                 = 7,
    BFD_DIAG_REV_CONCAT_PATH_DOWN       = 8
};

enum bfd_state {
    BFD_STATE_ADMIN_DOWN                = 0,
    BFD_STATE_DOWN                      = 1,
    BFD_STATE_INIT                      = 2,
    BFD_STATE_UP                        = 3
};

/* Parameters for a new BFD session */
struct bfd_session_params {
    char *src_ip;                           /* Source IP in string format (IPv4/IPv6) */
    char *dst_ip;                           /* Destination IP in string format (IPv4/IPv6) */
    bool is_ipv6;                           /* Flag to select type of IP session */
    uint32_t des_min_tx_interval;           /* Desired min TX interval for current session, BFD specific */
    uint32_t req_min_rx_interval;           /* Required min RX interval for current session, BFD specific */
    uint32_t detect_mult;                   /* Detection multiplier for current session, BFD specific */
    void (*callback)(void);                 /* Callback for different state changes? */
    struct bfd_session *current_session;    /* Pointer to current BFD session */
    uint8_t dscp;                           /* IP differentiated services code point */
};

/* 
 * Structure to describe a BFD session with all the state variables. While we could describe this in the bigger
 * one with all the parameters, probably better to encapsulate it separately for the moment.
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
    uint32_t detection_time;
    uint32_t remote_detect_mult;
    bool local_poll;
    bool local_final;
    bool remote_poll;
    bool remote_final;
};

/* Add a typedef for a BFD session ID */
typedef long int bfd_session_id;

/* Function prototypes */
bfd_session_id bfd_session_start(struct bfd_session_params *params);
void bfd_session_stop(bfd_session_id session_id);

#endif //BFD_SESSION_H_