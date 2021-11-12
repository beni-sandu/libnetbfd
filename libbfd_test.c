#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "bfd_session.h"

void bfd_callback() {}

int main(void) {
    
    bfd_session_id s1, s2;

    struct bfd_session_params s1_params = {
        .callback = &bfd_callback,
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 1,
        .dst_ip = "192.168.1.2",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.1.1",
    };

    struct bfd_session_params s2_params = {
        .callback = &bfd_callback,
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 2,
        .dst_ip = "fec0:0:0:f101::2",
        .is_ipv6 = true,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "fec0:0:0:f101::1",
    };

    //s1 = bfd_session_start(&s1_params);
    s2 = bfd_session_start(&s2_params);

/*
    if (s1 > 0)
        printf("BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld\n", s1_params.src_ip, s1_params.dst_ip, s1);
    else
        printf("Error starting BFD session for IP: %s\n", s1_params.src_ip);
*/

    if (s2 > 0)
        printf("BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld\n", s2_params.src_ip, s2_params.dst_ip, s2);
    else
        printf("Error starting BFD session for IP: %s\n", s2_params.src_ip);
    
    sleep(60);

    bfd_session_stop(s1);
}