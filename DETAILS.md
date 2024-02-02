The library currently supports Asynchronous mode with no authentication.

Supported parameters for a BFD session
--------------------------------------
- src_ip - Source IP in string format (IPv4/IPv6)
- dst_ip - Destination IP in string format (IPv4/IPv6)
- is_ipv6 - Boolean flag to select type of IP session (IPv4/IPv6)
- des_min_tx_interval - Desired min TX interval for the session, BFD specific parameter, provided in us
- req_min_rx_interval - Required min RX interval for the session, BFD specific parameter, provided in us
- detect_mult - Detection multiplier for the session, BFD specific parameter
- callback - Callback function for the session, to act on state changes
- dscp - IP differentiated services code point
- net_ns - Network namespace in string format
- src_port - Source port for the session
- log_file - Path to a file that can be used to store log messages

These are provided as a parameter structure, e.g.:

```c
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
```

Library interfaces
------------------
```c
/*
 * Create a new BFD session.
 *
 * @params: pointer to a parameter structure.
 * 
 * Returns a valid session id on successful creation or
 * -1 if an error occured.
 */
bfd_session_id bfd_session_start(struct bfd_session_params *params);


/*
 * Print details for a BFD session that has been started.
 * 
 * @session_id: a BFD session id
 * 
 * If an invalid session id is provided, it will print an error message,
 * otherwise details similar to below:
 * ---------------------------------------------
 * Timestamp:                02-Jun-2022 11:42:05
 * Session ID:               140479206323968
 * Source IP:                192.168.2.1
 * Destination IP:           192.168.2.2
 * Source port:              49152
 * Destination port:         3784
 * DSCP:                     16
 * Des min TX interval:      1000000
 * Req min RX interval:      1000000
 * Detection Multiplier:     1
 * My discriminator:         0x25227654
 * Current state:            BFD_STATE_DOWN
 * Operational TX:           1000000
 * Detection time:           1000000
 * ---------------------------------------------
 */
void bfd_session_print_stats(bfd_session_id session_id);


/* 
 * Similar behaviour to bfd_session_print_stats, but will instead print
 * the details to the log file specified in session parameters.
 */
void bfd_session_print_stats_log(bfd_session_id session_id);


/* 
 * Modify a BFD session that has been started.
 * 
 * @session_id:             a BFD session id
 * @cmd:                    type of command to modify the session with, which can be:
 *                                  - SESSION_ENABLE_ADMIN_DOWN - Put the session into ADMIN_DOWN state
 *                                  - SESSION_DISABLE_ADMIN_DOWN - Get the session out of ADMIN_DOWN state
 *                                  - SESSION_CHANGE_BFD_INTERVALS - Change the value of either Desired min TX interval
 *                                      or Required min RX interval
 * @des_min_tx_interval:    new value for Desired min TX interval when using SESSION_CHANGE_BFD_INTERVALS
 * @req_min_rx_interval:    new value for Required min RX interval when using SESSION_CHANGE_BFD_INTERVALS
 */
void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval);


/*
 * Change parameter of running session.
 *
 * @session_id:             BFD session id
 * @param:                  parameter that needs to be changed, currently supporting:
 *                                  - PARAM_DSCP - IP differentiated services code point
 *                                  - PARAM_DETECT_MULT - BFD session Detection Multiplier
 * @new_value:              updated value for the parameter that needs to be changed
 */
void bfd_session_change_param(bfd_session_id session_id, enum bfd_param param, uint32_t new_value);


/* 
 * Stop a BFD session that has been started.
 * 
 * @session_id: a BFD session id
 */
void bfd_session_stop(bfd_session_id session_id);


/*
 * Get value of local diagnostic code from session.
 *
 * @session_id:             BFD session id
 */
int bfd_session_get_local_diag(bfd_session_id session_id);


/*
 * Get value of current local state from session.
 *
 * @session_id:             BFD session id
 */
int bfd_session_get_local_state(bfd_session_id session_id);


/*
 * Return a string describing library version.
 */
const char *netbfd_lib_version(void);
```