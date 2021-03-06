#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <libnetbfd/libnetbfd.h>

/* Prototypes */
void bfd_callback(struct cb_status *status);
void bfd_callback_log(struct cb_status *status);

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

void bfd_callback_log(struct cb_status *status) {
    /*
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
     */

    switch (status->cb_ret) {
        case 1:
            print_log(status->session_params->log_file, "Detected BFD remote [%s] going DOWN\n", status->session_params->dst_ip);
            break;
        case 2:
            print_log(status->session_params->log_file, "Session [%s <--> %s] going to INIT.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case 3:
            print_log(status->session_params->log_file, "Session [%s <--> %s] going to UP.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case 4:
            print_log(status->session_params->log_file, "Remote [%s] signaled going DOWN\n", status->session_params->dst_ip);
            break;
        case 5:
            print_log(status->session_params->log_file, "Remote [%s] signaled going ADMIN_DOWN\n", status->session_params->dst_ip);
            break;
    }
}

int main(void) {
    
    bfd_session_id s1 = 0, s2 = 0;

    struct bfd_session_params s1_params = {
        .callback = &bfd_callback_log,
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 1,
        .dst_ip = "192.168.2.1",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.2.2",
        .dscp = 16, //OAM (CS2)
        .log_file = "/home/beni/bfd.log",
    };

    struct bfd_session_params s2_params = {
        .callback = &bfd_callback_log,
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 2,
        .dst_ip = "192.168.2.4",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.2.3",
        .dscp = 16, //OAM (CS2)
        .log_file = "/home/beni/bfd.log",
    };

    printf("Running with: %s\n", netbfd_lib_version());
    pr_debug("NOTE: You are using a debug build.\n");

    s1 = bfd_session_start(&s1_params);
    s2 = bfd_session_start(&s2_params);

    if (s1 > 0)
        print_log(s1_params.log_file, "BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld, src_port: %d\n", s1_params.src_ip,
                    s1_params.dst_ip, s1, s1_params.current_session->src_port);
    else
        print_log(s1_params.log_file, "Error starting BFD session for IP: %s\n", s1_params.src_ip);

    if (s2 > 0)
        print_log(s2_params.log_file, "BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld, src_port: %d\n", s2_params.src_ip,
                    s2_params.dst_ip, s2, s2_params.current_session->src_port);
    else
        print_log(s2_params.log_file, "Error starting BFD session for IP: %s\n", s2_params.src_ip);
    
    sleep(5);

    bfd_session_print_stats_log(s1);
    bfd_session_print_stats_log(s2);

    sleep(30);

    bfd_session_stop(s1);
    bfd_session_stop(s2);
}
