#include <libnetbfd/libnetbfd.h>

int main(void)
{
    bfd_session_id s1 = 0, s2 = 0;
    int test_status = 0;

    struct bfd_session_params s1_params = {
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 1,
        .dst_ip = "192.168.4.1",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.4.2",
        .dscp = 48, //Network control (CS6)
    };

    struct bfd_session_params s2_params = {
        .des_min_tx_interval = 1000000,   //in us
        .detect_mult = 1,
        .dst_ip = "192.168.4.2",
        .is_ipv6 = false,
        .req_min_rx_interval = 1000000,   //in us
        .src_ip = "192.168.4.1",
        .dscp = 48, //Network control (CS6)
    };

    printf("Running with: %s\n", netbfd_lib_version());
    bfd_pr_debug(NULL, "NOTE: You are using a debug build.\n");

    /* Start the first session */
    s1 = bfd_session_start(&s1_params);

    /* Check local state */
    if (bfd_session_get_local_state(s1) == BFD_STATE_DOWN)
        printf("PASS: get session local state (case 1).\n");
    else {
        printf("FAIL: get session local state (case 1).\n");
        test_status = -1;
    }

    /* Check local diag */
    if (bfd_session_get_local_diag(s1) == BFD_DIAG_NODIAG)
        printf("PASS: get session local diag (case 1).\n");
    else {
        printf("FAIL: get session local diag (case 1).\n");
        test_status = -1;
    }

    /* Start 2nd session */
    s2 = bfd_session_start(&s2_params);
    sleep(2);

    /* Local state should be UP */
    if (bfd_session_get_local_state(s1) == BFD_STATE_UP)
        printf("PASS: get session local state (case 2).\n");
    else {
        printf("FAIL: get session local state (case 2).\n");
        test_status = -1;
    }

    /* Stop 2nd session and check diag again */
    bfd_session_stop(s2);
    sleep(2);
    if (bfd_session_get_local_diag(s1) == BFD_DIAG_CTRL_DETECT_TIME_EXPIRED)
        printf("PASS: get session local diag (case 2).\n");
    else {
        printf("FAIL: get session local diag (case 2).\n");
        test_status = -1;
    }

    return test_status;
}
