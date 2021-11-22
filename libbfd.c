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


void bfd_session_modify(struct bfd_session_params *session, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval) {

    switch (cmd) {
        case SESSION_ENABLE_ADMIN_DOWN:
            if (session->current_session->local_state != BFD_STATE_ADMIN_DOWN) {
                pr_debug("Putting session [%s <--> %s] into ADMIN_DOWN\n", session->src_ip, session->dst_ip);
                session->current_session->local_state = BFD_STATE_ADMIN_DOWN;
            }
            else
                pr_debug("Session [%s <--> %s] is already in ADMIN_DOWN, skipping.\n", session->src_ip, session->dst_ip);
            break;

        case SESSION_DISABLE_ADMIN_DOWN:
            if (session->current_session->local_state == BFD_STATE_ADMIN_DOWN) {
                pr_debug("Getting session [%s <--> %s] out of ADMIN_DOWN\n", session->src_ip, session->dst_ip);
                session->current_session->local_state = BFD_STATE_DOWN;
            }
            else
                pr_debug("Session [%s <--> %s] was not in ADMIN_DOWN, skipping.\n", session->src_ip, session->dst_ip);
            break;

        case SESSION_CHANGE_PARAMS:
            pr_debug("Parameter change requested for session [%s <--> %s], initiating Poll Sequence.\n", session->src_ip, session->dst_ip);
            
            if (des_min_tx_interval == 0 && req_min_rx_interval == 0) {
                pr_debug("Both parameters are 0, no Poll Sequence required.\n");
                return;
            }

            if (des_min_tx_interval > 0)
                session->des_min_tx_interval = des_min_tx_interval;

            if (req_min_rx_interval > 0)
                session->req_min_rx_interval = req_min_rx_interval;
            
            session->current_session->poll_in_progress = true;
            break;
        
        default:
            pr_debug("Invalid bfd_session_modify command.\n");
            break;
    }
}

/* 
 * Search a device on the local system, given an IP address as input.
 *
 * Return 0 on success and name is copied in 3rd argument or 
 * -1 if something failed or no interface is found with that IP.
 * 
 * There is probably a better way to do this, but good enough for now. :)
 */
int search_device_by_ip(char *ip, bool is_ipv6, char *device) {
    
    struct ifaddrs *addrs, *ifp;
    struct sockaddr_in *sav4;
    struct sockaddr_in6 *sav6;
    char ip_buf[32];
    
    /* Get a list of network interfaces on the local system */
    if (getifaddrs(&addrs) == -1) {
        perror("getifaddrs: ");
        return EXIT_FAILURE;
    }
    
    /* Use a crawler pointer, so we can free the list anytime */
    ifp = addrs;

    while (ifp != NULL) {
        if (is_ipv6 == true) {
            if (ifp->ifa_addr != NULL && ifp->ifa_addr->sa_family == AF_INET6) {
                sav6 = (struct sockaddr_in6 *)(ifp->ifa_addr);
                inet_ntop(ifp->ifa_addr->sa_family, (void *)&sav6->sin6_addr, ip_buf, sizeof(ip_buf));
            }
        } else {
            if (ifp->ifa_addr != NULL && ifp->ifa_addr->sa_family == AF_INET) {
                sav4 = (struct sockaddr_in *)(ifp->ifa_addr);
                inet_ntop(ifp->ifa_addr->sa_family, (void *)&sav4->sin_addr, ip_buf, sizeof(ip_buf));
            }
        }
        
        if (strcmp(ip, ip_buf) == 0) {
            strcpy(device, ifp->ifa_name);
            freeifaddrs(addrs);
            return EXIT_SUCCESS;
        }
        ifp = ifp->ifa_next;
    }

    /* If no interface was found, free the list and return */
    if (addrs != NULL)
        freeifaddrs(addrs);

    return EXIT_FAILURE;
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

char *get_time(char *t_now) {
    time_t now;
	struct tm *local = NULL;
	char timestamp[100];

    now = time(NULL);
	local = localtime(&now);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", local);
    
    strcpy(t_now, timestamp);

    return t_now;
}