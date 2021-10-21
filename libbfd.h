#include <libnet.h>

#include "bfd_packet.h"

#define DEBUG_ENABLE

#ifdef DEBUG_ENABLE
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug(...)
#endif

/* Data passed to per thread timer */
struct bfd_timer {
    timer_t timer_id;                                       /* POSIX interval timer id */
    bool send_next_pkt;                                     /* Flag to control packet transaction */
    struct bfd_session_params *sess_params;                 /* pointer to current BFD session parameters if needed */
};

/* Wrapper to update UDP header */
static inline void bfd_build_udp(struct bfd_ctrl_packet *pkt, libnet_ptag_t *udp_tag, libnet_t *l) {
    
    *udp_tag = libnet_build_udp(
        BFD_SRC_PORT_MIN,                                   /* Source port, TODO: needs to be unique for every session */
        BFD_CTRL_PORT,                                      /* Destination port */
        LIBNET_UDP_H + BFD_PKG_MIN_SIZE,                    /* Packet lenght */
        0,                                                  /* Checksum */
        (uint8_t *)pkt,                                     /* Payload */
        BFD_PKG_MIN_SIZE,                                   /* Payload size */
        l,                                                  /* libnet handle */
        *udp_tag);                                          /* libnet tag */

    if (*udp_tag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
}

/* Function prototypes */
int search_device_by_ip(char *ip, bool is_ipv6, char *device);
int bfd_start_tx_timer(struct bfd_timer *timer_data, struct itimerspec *ts);
int bfd_update_tx_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *btimer);