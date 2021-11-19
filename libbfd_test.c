#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "bfd_session.h"
#include "libbfd.h"

void bfd_callback(struct cb_status *status) {
    /*
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
     */

    switch (status->cb_ret) {
        case 1:
            printf("Detected BFD remote [%s] going DOWN\n", status->session_params->dst_ip);
            break;
        case 2:
            printf("Session [%s <--> %s] going to INIT.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case 3:
            printf("Session [%s <--> %s] going to UP.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case 4:
            printf("Remote [%s] signaled going DOWN\n", status->session_params->dst_ip);
            break;
        case 5:
            printf("Remote [%s] signaled going ADMIN_DOWN\n", status->session_params->dst_ip);
            break;
    }
}

int main(void) {
    
    bfd_session_id s1 = 0, s2 = 0;

    struct bfd_session_params s1_params = {
        .callback = &bfd_callback,
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 1,
        .dst_ip = "192.168.1.2",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.1.1",
        .dscp = 8, //Low-priority data (CS1)
    };

    struct bfd_session_params s2_params = {
        .callback = &bfd_callback,
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 2,
        .dst_ip = "fec0:0:0:f101::2",
        .is_ipv6 = true,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "fec0:0:0:f101::1",
        .dscp = 16, //OAM (CS2)
    };

    s1 = bfd_session_start(&s1_params);
    s2 = bfd_session_start(&s2_params);

    if (s1 > 0)
        printf("BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld\n", s1_params.src_ip, s1_params.dst_ip, s1);
    else
        printf("Error starting BFD session for IP: %s\n", s1_params.src_ip);

    if (s2 > 0)
        printf("BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld\n", s2_params.src_ip, s2_params.dst_ip, s2);
    else
        printf("Error starting BFD session for IP: %s\n", s2_params.src_ip);
    
    /* Wait 5s, put session s1 into ADMIN_DOWN */
    sleep(5);
    bfd_session_modify(&s1_params, SESSION_ENABLE_ADMIN_DOWN, 0, 0);

    /* After another 5s, get s1 out of ADMIN_DOWN */
    sleep(5);
    bfd_session_modify(&s1_params, SESSION_DISABLE_ADMIN_DOWN, 0, 0);

    sleep(30);
    bfd_session_stop(s1);
    bfd_session_stop(s2);
}