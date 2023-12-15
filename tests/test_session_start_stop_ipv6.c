#include <libnetbfd/libnetbfd.h>

int main(void)
{
    bfd_session_id s1 = 0, s2 = 0;
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

    struct bfd_session_params s2_params = {
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 3,
        .dst_ip = "2001:db8::1:100",
        .is_ipv6 = true,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "2001:db8::1:101",
        .dscp = 48, //Network control (CS6)
    };

    printf("Running with: %s\n", netbfd_lib_version());
    bfd_pr_debug(NULL, "NOTE: You are using a debug build.\n");

    /* Start the first session */
    s1 = bfd_session_start(&s1_params);

    if (s1 > 0)
        printf("BFD session started successfully: [%s <--> %s]\n", s1_params.src_ip, s1_params.dst_ip);
    else {
        printf("Error starting BFD session: [%s <--> %s]\n", s1_params.src_ip, s1_params.dst_ip);
        test_status = -1;
    }
    
    /* Start the second session */
    s2 = bfd_session_start(&s2_params);

    if (s2 > 0)
        printf("BFD session started successfully: [%s <--> %s]\n", s2_params.src_ip, s2_params.dst_ip);
    else {
        printf("Error starting BFD session: [%s <--> %s]\n", s2_params.src_ip, s2_params.dst_ip);
        test_status = -1;
    }

    sleep(1);

    bfd_session_stop(s1);
    bfd_session_stop(s2);

    return test_status;
}
