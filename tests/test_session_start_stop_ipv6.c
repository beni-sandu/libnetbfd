#include "../include/libnetbfd.h"

int main(void)
{
    bfd_session_id s1 = 0;
    int test_status = 0;

    struct bfd_session_params s1_params = {
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 3,
        .dst_ip = "2001:db8::1:101",
        .is_ipv6 = true,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "2001:db8::1:100",
        .dscp = 48, //Network control (CS6)
    };

    printf("Running with: %s\n", netbfd_lib_version());
    bfd_pr_debug(NULL, "NOTE: You are using a debug build.\n");

    /* Start the first session */
    s1 = bfd_session_start(&s1_params);

    if (s1 > 0)
        printf("PASS: session start IPv6.\n");
    else {
        printf("FAIL: session start IPv6.\n");
        test_status = -1;
    }

    sleep(2);
    bfd_session_stop(s1);
    printf("PASS: session stop IPv6.\n");

    return test_status;
}
