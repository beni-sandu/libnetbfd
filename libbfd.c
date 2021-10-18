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

/* Start per thread timer */
int bfd_start_timer(struct bfd_timer *timer_data, struct itimerspec *ts) {

    if (timer_settime(timer_data->timer_id, 0, ts, 0) == -1) {
        perror("timer settime");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int bfd_update_timer(int interval_us, struct itimerspec *ts, struct bfd_timer *timer_data) {

    /* Update timer interval */
    ts->it_interval.tv_sec = (interval_us > 999999) ? (interval_us / 1000000) : 0;
    ts->it_interval.tv_nsec = (interval_us > 999999) ? (interval_us % 1000000 * 1000000)
                                : (interval_us * 1000);
    ts->it_value.tv_sec = (interval_us > 999999) ? (interval_us / 1000000) : 0;
    ts->it_value.tv_nsec = (interval_us > 999999) ? (interval_us % 1000000 * 1000000)
                                : (interval_us * 1000);
    
    if (timer_settime(timer_data->timer_id, 0, ts, 0) == -1) {
        perror("timer settime");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}