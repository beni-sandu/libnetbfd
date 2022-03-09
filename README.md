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
This library depends on libnet, so make sure that is available first (e.g. on Debian derived systems):

```sh
$ sudo apt install libnet1
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
//Add a callback to act on state changes
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

//Fill in needed parameters for the BFD session
bfd_session_id s1 = 0;

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

//Start the session:
s1 = bfd_session_start(&s1_params);

//Error checking
if (s1 > 0)
        printf("BFD session started successfully, local IP: %s, remote IP: %s, session id: %ld, src_port: %d\n", s1_params.src_ip,
                    s1_params.dst_ip, s1, s1_params.current_session->src_port);
    else
        printf("Error starting BFD session for IP: %s\n", s1_params.src_ip);

//Do your work here...

//Stop the session
bfd_session_stop(s1);
```

More details about the available interfaces and parameters can be found here:
- [DETAILS.md](DETAILS.md)