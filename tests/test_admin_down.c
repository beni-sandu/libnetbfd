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

    /* Start the sessions */
    s1 = bfd_session_start(&s1_params);
    s2 = bfd_session_start(&s2_params);

    /* Put one session in ADMIN_DOWN */
    sleep(1);
    bfd_session_modify(s1, SESSION_ENABLE_ADMIN_DOWN, 0, 0);
    sleep(1);

    /* Check local state */
    if (bfd_session_get_local_state(s1) == BFD_STATE_ADMIN_DOWN)
        printf("PASS: session enable ADMIN_DOWN (case 1).\n");
    else {
        printf("FAIL: session enable ADMIN_DOWN (case 1).\n");
        test_status = -1;
    }

    /* Check local diag */
    if (bfd_session_get_local_diag(s1) == BFD_DIAG_ADMIN_DOWN)
        printf("PASS: session enable ADMIN_DOWN (case 2).\n");
    else {
        printf("FAIL: session enable ADMIN_DOWN (case 2).\n");
        test_status = -1;
    }

    /* Local state for 2nd session should be DOWN */
    if (bfd_session_get_local_state(s2) == BFD_STATE_DOWN)
        printf("PASS: session enable ADMIN_DOWN (case 3).\n");
    else {
        printf("FAIL: session enable ADMIN_DOWN (case 3).\n");
        test_status = -1;
    }

    /* Local diag for 2nd session should be "Neighbour signaled session down" */
    if (bfd_session_get_local_diag(s2) == BFD_DIAG_NEIGH_SIGNL_SESS_DOWN)
        printf("PASS: session enable ADMIN_DOWN (case 4).\n");
    else {
        printf("FAIL: session enable ADMIN_DOWN (case 4).\n");
        test_status = -1;
    }

    /* Disable ADMIN_DOWN for 1st session */
    bfd_session_modify(s1, SESSION_DISABLE_ADMIN_DOWN, 0, 0);
    sleep(2);

    /* State of 1st session should be UP */
    if (bfd_session_get_local_state(s1) == BFD_STATE_UP)
        printf("PASS: session disable ADMIN_DOWN (case 1).\n");
    else {
        printf("FAIL: session disable ADMIN_DOWN (case 1).\n");
        test_status = -1;
    }

    /* State of 2nd session should be UP */
    if (bfd_session_get_local_state(s2) == BFD_STATE_UP)
        printf("PASS: session disable ADMIN_DOWN (case 2).\n");
    else {
        printf("FAIL: session disable ADMIN_DOWN (case 2).\n");
        test_status = -1;
    }

    /* Diag of 1st session should be NO_DIAG */
    if (bfd_session_get_local_diag(s1) == BFD_DIAG_NODIAG)
        printf("PASS: session disable ADMIN_DOWN (case 3).\n");
    else {
        printf("FAIL: session disable ADMIN_DOWN (case 3).\n");
        test_status = -1;
    }

    /* Diag of 2nd session should be NO_DIAG */
    if (bfd_session_get_local_diag(s2) == BFD_DIAG_NODIAG)
        printf("PASS: session disable ADMIN_DOWN (case 4).\n");
    else {
        printf("FAIL: session disable ADMIN_DOWN (case 4).\n");
        test_status = -1;
    }

    return test_status;
}
