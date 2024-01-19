/*
 * Copyright: Beniamin Sandu <beniaminsandu@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * BFD protocol specifics from:
 * RFC5880 (https://datatracker.ietf.org/doc/html/rfc5880)
 * RFC5881 (https://datatracker.ietf.org/doc/html/rfc5881)
 *
 * Generic BFD Control Packet Format:
 *
 * Mandatory section (yes, I numbered every bit, get over it):
 *
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       My Discriminator                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Your Discriminator                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Desired Min TX Interval                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Required Min RX Interval                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Required Min Echo RX Interval                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef _BFD_PACKET_H
#define _BFD_PACKET_H

#include <stdint.h>
#include <arpa/inet.h>
#include "bfd_session.h"

/* BFD control packet length without authentication, in bytes */
#define BFD_PKG_MIN_SIZE    24

/* Authentication section not present (currently not supported) */
struct bfd_ctrl_packet {
    union {
        uint8_t version;                        /* Protocol version (always 1) */
        uint8_t diag;                           /* Diagnostic code for last session state change */
    } byte1;
    union {
        uint8_t state;                          /* Current BFD session state */
        uint8_t poll;
        uint8_t final;
        uint8_t ctrl_plane_independent;
        uint8_t auth_present;                   /* Authentication present */
        uint8_t demand;                         /* Demand mode */
        uint8_t multipoint;                     /* Multipoint (not supported) */
    } byte2;
    uint8_t detect_mult;                        /* Detection time multiplier */
    uint8_t length;                             /* Length of BFD control packet in bytes */
    uint32_t my_discr;                          /* My discriminator, unique per session value */
    uint32_t your_discr;                        /* Your discriminator, received from corresponding remote system */
    uint32_t des_min_tx_interval;               /* Desired min TX interval, in microseconds (RFC5880: section 6.8.2 for details) */
    uint32_t req_min_rx_interval;               /* Required min RX interval, in microseconds (RFC5880: section 6.8.2 for details) */
    uint32_t req_min_echo_rx_interval;          /* Required min echo RX interval, in microseconds (RFC5880: section 6.8.9 for details) */
} __attribute__((__packed__));

/* Function prototypes */
void bfd_build_packet(enum bfd_diag diag, enum bfd_state state, bool poll, bool final, uint8_t detect_mult,
                uint32_t my_discr, uint32_t your_discr, uint32_t des_min_tx_interval, uint32_t req_min_rx_interval,
                struct bfd_ctrl_packet *packet);

#endif // _BFD_PACKET_H
