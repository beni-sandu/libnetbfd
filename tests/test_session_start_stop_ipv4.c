#include "../include/libnetbfd.h"

int main(void)
{
    bfd_session_id s1 = 0;
    int test_status = 0;

    struct bfd_session_params s1_params = {
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 3,
        .dst_ip = "192.168.4.1",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.4.2",
        .dscp = 48, //Network control (CS6)
    };

    printf("Running with: %s\n", netbfd_lib_version());
    bfd_pr_debug(NULL, "NOTE: You are using a debug build.\n");

    /* Start the first session */
    s1 = bfd_session_start(&s1_params);

    if (s1 > 0)
        printf("PASS: session start IPv4.\n");
    else {
        printf("FAIL: session start IPv4.\n");
        test_status = -1;
    }

    sleep(2);
    bfd_session_stop(s1);
    printf("PASS: session stop IPv4.\n");

    return test_status;
}
