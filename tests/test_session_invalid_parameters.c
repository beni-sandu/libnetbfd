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

    /* Test invalid source IPv4. */
    strcpy(s1_params.src_ip, "192.168.4");
    s1 = bfd_session_start(&s1_params);

    if (s1 == -1)
        printf("PASS: invalid source IPv4.\n");
    else {
        printf("FAIL: invalid source IPv4.\n");
        test_status = -1;
    }
    strcpy(s1_params.src_ip, "192.168.4.1");

    /* Test invalid destination IPv4. */
    strcpy(s1_params.dst_ip, "192.168.4.");
    s1 = bfd_session_start(&s1_params);

    if (s1 == -1)
        printf("PASS: invalid destination IPv4.\n");
    else {
        printf("FAIL: invalid destination IPv4.\n");
        test_status = -1;
    }
    strcpy(s1_params.dst_ip, "192.168.4.2");

    /* Test invalid source IPv6. */
    s1_params.is_ipv6 = true;
    strcpy(s1_params.dst_ip, "2001:db8::1:101");
    s1 = bfd_session_start(&s1_params);

    if (s1 == -1)
        printf("PASS: invalid source IPv6.\n");
    else {
        printf("FAIL: invalid source IPv6.\n");
        test_status = -1;
    }
    strcpy(s1_params.src_ip, "2001:db8::1:100");

    /* Test invalid destination IPv6. */
    strcpy(s1_params.dst_ip, "2001:db8:::1:101");
    s1 = bfd_session_start(&s1_params);

    if (s1 == -1)
        printf("PASS: invalid destination IPv6.\n");
    else {
        printf("FAIL: invalid destination IPv6.\n");
        test_status = -1;
    }
    strcpy(s1_params.dst_ip, "2001:db8::1:101");

    /* Test invalid network namespace. */
    strcpy(s1_params.net_ns, "net_ns");
    s1 = bfd_session_start(&s1_params);

    if (s1 == -1)
        printf("PASS: invalid network namespace.\n");
    else {
        printf("FAIL: invalid network namespace.\n");
        test_status = -1;
    }
    memset(s1_params.net_ns, 0, sizeof("net_ns"));

    /* Test source IP not assigned on any interface (this is assumed). */
    strcpy(s1_params.src_ip, "2001:db8::1:110");
    s1 = bfd_session_start(&s1_params);

    if (s1 == -1)
        printf("PASS: source IP not assigned on any interface.\n");
    else {
        printf("FAIL: source IP not assigned on any interface.\n");
        test_status = -1;
    }

    sleep(2);
    bfd_session_stop(s1);

    return test_status;
}
