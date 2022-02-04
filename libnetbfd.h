#include <libnet.h>
#include <semaphore.h>
#include <pthread.h>

#include "bfd_packet.h"

#define DEBUG_ENABLE

/* Library version */
#define LIBNETBFD_VERSION "0.1"

#ifdef DEBUG_ENABLE
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug(...)
#endif

#define max(a, b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

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
int search_device_by_ip(char *ip, bool is_ipv6, char *device);
int bfd_start_tx_timer(struct bfd_timer *timer_data, struct itimerspec *ts);
int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *btimer);
const char *state2string(enum bfd_state state);
char *get_time(char *t_now);
void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval);
bool is_ip_valid(char *ip, bool is_ipv6);
void bfd_add_session(struct bfd_session_node **head, struct bfd_session_node *new_node);
struct bfd_session_node *bfd_find_session(bfd_session_id session_id);
void bfd_session_print_stats(bfd_session_id session_id);
void bfd_remove_session(struct bfd_session_node **head_ref, bfd_session_id session_id);
const char *netbfd_lib_version(void);
