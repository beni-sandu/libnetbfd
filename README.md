Bidirectional Forwarding Detection (BFD) networking protocol
============================================================

libnetbfd is a minimalistic library implementation of the Bidirectional Forwarding Detection networking protocol, mainly based on 2 standards:

- [RFC8880](https://datatracker.ietf.org/doc/html/rfc5880)
- [RFC8881](https://datatracker.ietf.org/doc/html/rfc5881)

The protocol is intended to detect faults in the bidirectional path between two forwarding engines, including interfaces,
data link(s), and to the extent possible the forwarding engines themselves, with potentially very low latency.  It operates
independently of media, data protocols, and routing protocols.

Building and installing
-----------------------
Install needed dependencies first (e.g. on Debian derived systems):

```sh
$ sudo apt install libnet1-dev libcap-dev
```

Build and install libnetbfd:

```sh
$ git clone https://github.com/beni-sandu/libnetbfd.git
$ cd libnetbfd
$ make
$ sudo make install
```
After the library is installed, you can link it with your program using -lnetbfd.

Using the library
-----------------
Libnetbfd is installed as a shared library and a set of headers. The main header to use in your program is:

```c
#include <libnetbfd/libnetbfd.h>
```

Below is a code example of a typical workflow:

```c
// Add a callback to act on state changes
void bfd_callback(struct cb_status *status) {
    /*
     *  1 - Session detected the remote peer going DOWN (detection time expired)
     *  2 - Session is going to INIT
     *  3 - Session is going to UP
     *  4 - Remote signaled going DOWN
     *  5 - Remote signaled going ADMIN_DOWN
     *  6 - Source IP is not assigned, or the interface that is using it is DOWN
     *  7 - Session is going into ADMIN_DOWN state
     *  8 - Session is getting out of ADMIN_DOWN state
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
        case BFD_CB_IP_NOT_ASSIGN_OR_IF_DOWN:
            printf("Provided source IP is not assigned or the interface is DOWN.\n");
            break;
        case BFD_CB_SESSION_ENABLE_ADMIN_DOWN:
            printf("Session [%s <--> %s] going into ADMIN_DOWN.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
        case BFD_CB_SESSION_DISABLE_ADMIN_DOWN:
            printf("Session [%s <--> %s] getting out of ADMIN_DOWN.\n", status->session_params->src_ip, status->session_params->dst_ip);
            break;
    }
}

// Fill in needed parameters for the BFD session
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

// Start the session:
s1 = bfd_session_start(&s1_params);

// Error checking
if (s1 > 0)
    printf("BFD session started successfully: [%s <--> %s]\n", s1_params.src_ip, s1_params.dst_ip);
else
    printf("Error starting BFD session: [%s <--> %s]\n", s1_params.src_ip, s1_params.dst_ip);

// Do your work here...

// Stop the session
bfd_session_stop(s1);
```

More details about the available interfaces and parameters can be found here:
- [DETAILS.md](DETAILS.md)
