#include <libnet.h>
#ifdef __STDC_NO_ATOMICS__
# error this implementation needs atomics
#endif
#include <stdatomic.h>
#include <semaphore.h>
#include <pthread.h>

#include "bfd_packet.h"

#define DEBUG_ENABLE

#ifdef DEBUG_ENABLE
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug(...)
#endif

static atomic_ulong src_port = BFD_SRC_PORT_MIN;

#define max(a, b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

struct bfd_thread {
    sem_t sem;
    struct bfd_session_params *session_params;
    int ret;
};

/* Data passed to per thread timer */
struct bfd_timer {
    timer_t timer_id;                                       /* POSIX interval timer id */
    bool next_pkt;                                          /* Flag to control packet transaction */
    struct bfd_session_params *sess_params;                 /* pointer to current BFD session parameters if needed */
    struct bfd_ctrl_packet *pkt;
    libnet_ptag_t *udp_tag;
    libnet_t *l;
    struct itimerspec *tx_ts;
};

/* Wrapper to update UDP header */
static inline void bfd_build_udp(struct bfd_ctrl_packet *pkt, libnet_ptag_t *udp_tag, libnet_t *l) {
    
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
int search_device_by_ip(char *ip, bool is_ipv6, char *device);
int bfd_start_tx_timer(struct bfd_timer *timer_data, struct itimerspec *ts);
int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *btimer);
char *state2string(enum bfd_state state);
char *get_time(char *t_now);