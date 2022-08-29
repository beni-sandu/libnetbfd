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
     *  6 - Source IP is not assigned, or the interface that is using it is DOWN
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
        case 6:
            printf("Provided source IP is not assigned or the interface is DOWN.\n");
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
