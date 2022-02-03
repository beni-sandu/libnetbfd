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

#include "libbfd.h"
#include "bfd_packet.h"
#include "bfd_session.h"

/* Globals */
struct bfd_session_node *head = NULL;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval) {
    
    struct bfd_session_node *session = bfd_find_session(session_id);

    if (session == NULL) {
        fprintf(stderr, "Could not find a valid BFD session with that id.\n");
        return;
    }

    switch (cmd) {
        case SESSION_ENABLE_ADMIN_DOWN:

            pthread_rwlock_wrlock(&rwlock);
            if (session->session_params->current_session->local_state != BFD_STATE_ADMIN_DOWN) {
                pr_debug("Putting session: %ld into ADMIN_DOWN.\n", session_id);
                session->session_params->current_session->local_state = BFD_STATE_ADMIN_DOWN;
            }
            else
                pr_debug("Session: %ld is already in ADMIN_DOWN, skipping.\n", session_id);
            pthread_rwlock_unlock(&rwlock);

            break;

        case SESSION_DISABLE_ADMIN_DOWN:

            pthread_rwlock_wrlock(&rwlock);
            if (session->session_params->current_session->local_state == BFD_STATE_ADMIN_DOWN) {
                pr_debug("Getting session: %ld out of ADMIN_DOWN.\n", session_id);
                session->session_params->current_session->local_state = BFD_STATE_DOWN;
            }
            else
                pr_debug("Session: %ld was not in ADMIN_DOWN, skipping.\n", session_id);
            pthread_rwlock_unlock(&rwlock);

            break;

        case SESSION_CHANGE_PARAMS:

            if (des_min_tx_interval == 0 && req_min_rx_interval == 0) {
                fprintf(stderr, "Both parameters are 0, nothing to be done.\n");
                return;
            }

            pr_debug("Parameter change requested for session [%s <--> %s], initiating Poll Sequence.\n", session->session_params->src_ip, session->session_params->dst_ip);

            /* Is it a good idea to change both of them at the same time? Time(testing) will tell */
            pthread_rwlock_wrlock(&rwlock);
            if (des_min_tx_interval > 0)
                session->session_params->des_min_tx_interval = des_min_tx_interval;

            if (req_min_rx_interval > 0)
                session->session_params->req_min_rx_interval = req_min_rx_interval;
            
            session->session_params->current_session->poll_in_progress = true;
            pthread_rwlock_unlock(&rwlock);

            break;

        default:
            fprintf(stderr, "Invalid bfd_session_modify command.\n");
            break;
    }
}

int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *timer_data) {

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

const char *state2string(enum bfd_state state) {

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

bool is_ip_valid(char *ip, bool is_ipv6) {

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

void bfd_add_session(struct bfd_session_node **head_ref, struct bfd_session_node *new_node) {

    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}

void bfd_remove_session(struct bfd_session_node **head_ref, bfd_session_id session_id) {

    struct bfd_session_node *it = *head_ref, *prev;
 
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

struct bfd_session_node *bfd_find_session(bfd_session_id session_id) {

    pthread_rwlock_rdlock(&rwlock);
    struct bfd_session_node *it = head;

    while (it != NULL) {
        if (it->session_params->current_session->session_id == session_id) {
            pthread_rwlock_unlock(&rwlock);
            return it;
        }
        it = it->next;
    }

    pthread_rwlock_unlock(&rwlock);
    return NULL;
}

void bfd_session_print_stats(bfd_session_id session_id) {

    struct bfd_session_node *session = bfd_find_session(session_id);

    if (session == NULL) {
        fprintf(stderr, "Could not find a valid BFD session with that id.\n");
        return;
    }

    printf("---------------------------------------------\n");
    printf("%-25s %ld\n", "Session ID:", session->session_params->current_session->session_id);
    printf("%-25s %s\n", "Source IP:", session->session_params->src_ip);
    printf("%-25s %s\n", "Destination IP:", session->session_params->dst_ip);
    printf("%-25s %d\n", "Source port:", session->session_params->current_session->src_port);
    printf("%-25s %d\n", "DSCP:", session->session_params->dscp);
    printf("%-25s %d\n", "Des min TX interval:", session->session_params->current_session->des_min_tx_interval);
    printf("%-25s %d\n", "Req min RX interval:", session->session_params->current_session->req_min_rx_interval);
    printf("%-25s 0x%x\n", "My discriminator:", session->session_params->current_session->local_discr);
    printf("%-25s %s\n", "Current state:", state2string(session->session_params->current_session->local_state));
    printf("%-25s %d\n", "Operational TX:", session->session_params->current_session->op_tx);
    printf("%-25s %d\n", "Detection time:", session->session_params->current_session->detection_time);
    printf("---------------------------------------------\n");
}

/* Return library version */
const char *bfd_lib_version(void) {

    return ("libbfd version " VER_MAJOR "." VER_MINOR);
}