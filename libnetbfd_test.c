#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <libnetbfd/libnetbfd.h>

/* Prototypes */
void bfd_callback(struct cb_status *status);

void bfd_callback(struct cb_status *status) {
    /*
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
     *  6 - Interface that is using the source IP is DOWN
     *  7 - Session is going into ADMIN_DOWN state
     *  8 - Session is getting out of ADMIN_DOWN state
     *  9 - Provided source IP is not assigned on any interface
     */

    switch (status->cb_ret) {
        case BFD_CB_DETECT_TIME_EXPIRED:
            printf("Detected BFD remote [%s] going DOWN\n", status->session_params->dst_ip);
            break;
        case BFD_CB_SESSION_INIT:
            printf("Session [%s <--> %s] going to INIT.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case BFD_CB_SESSION_UP:
            printf("Session [%s <--> %s] going to UP.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case BFD_CB_REMOTE_SIGN_DOWN:
            printf("Remote [%s] signaled going DOWN\n", status->session_params->dst_ip);
            break;
        case BFD_CB_REMOTE_SIGN_ADMIN_DOWN:
            printf("Remote [%s] signaled going ADMIN_DOWN\n", status->session_params->dst_ip);
            break;
        case BFD_CB_INTERFACE_DOWN:
            printf("Interface using the source IP is DOWN.\n");
            break;
        case BFD_CB_SESSION_ENABLE_ADMIN_DOWN:
            printf("Session [%s <--> %s] going into ADMIN_DOWN.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case BFD_CB_SESSION_DISABLE_ADMIN_DOWN:
            printf("Session [%s <--> %s] getting out of ADMIN_DOWN.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case BFD_CB_SRC_IP_NOT_ASSIGNED:
            printf("Provided source IP is not assigned on any interface.\n");
            break;
    }
}

int main(void) {

    bfd_session_id s1 = 0;

    struct bfd_session_params s1_params = {
        .callback = &bfd_callback,
        .des_min_tx_interval = 500000,   //in us
        .detect_mult = 3,
        .dst_ip = "192.168.4.2",
        .is_ipv6 = false,
        .req_min_rx_interval = 500000,   //in us
        .src_ip = "192.168.4.1",
        .dscp = 48, //Network control (CS6)
    };

    printf("Running with: %s\n", netbfd_lib_version());
    pr_debug("NOTE: You are using a debug build.\n");

    s1 = bfd_session_start(&s1_params);

    if (s1 > 0)
        printf("BFD session started successfully: [%s <--> %s]\n", s1_params.src_ip, s1_params.dst_ip);
    else
        printf("Error starting BFD session: [%s <--> %s]\n", s1_params.src_ip, s1_params.dst_ip);

    sleep(60);

    bfd_session_stop(s1);
}
