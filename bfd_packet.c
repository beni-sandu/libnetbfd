/*
 * Copyright (C) 2022 Beniamin Sandu <beniaminsandu@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdbool.h>
#include "bfd_session.h"
#include "bfd_packet.h"

void bfd_build_packet(enum bfd_diag diag, enum bfd_state state, bool poll, bool final, uint8_t detect_mult,
                uint32_t my_discr, uint32_t your_discr, uint32_t des_min_tx_interval, uint32_t req_min_rx_interval,
                struct bfd_ctrl_packet *packet) {

    /* Protocol version, always 1 */
    packet->byte1.version = 0x20;
    
    /* Diagnostic code */
    packet->byte1.diag |= diag & 0x1F;

    /* Clear second byte, since most flags are disabled */
    packet->byte2.state = 0;

    /* Set BFD session state */
    packet->byte2.state = (state << 6) & 0xC0;

    /* Set Poll flag */
    packet->byte2.poll |= (poll << 5) & 0x20;

    /* Set Final flag */
    packet->byte2.final |= (final << 4) & 0x10;

    /* 
     * Detection time multiplier: The negotiated transmit interval, multiplied by this value,
     * provides the Detection Time for the receiving system in Asynchronous mode.
     */
    packet->detect_mult = detect_mult;

    /* Length of BFD control packet in bytes */
    packet->length = BFD_PKG_MIN_SIZE;

    /* My discriminator: unique value per session, generated by the transmitting system */
    packet->my_discr = htonl(my_discr);

    /*
     * Your discriminator: the discriminator value received from the corresponding remote system.
     * Zero if unknown.
     */
    packet->your_discr = htonl(your_discr);

    /* 
     * Desired min TX interval: minimum interval, in microseconds, that the local system would 
     * like to use when transmitting BFD Control packets,less any jitter applied (see section 6.8.2).
     */
    packet->des_min_tx_interval = htonl(des_min_tx_interval);

    /*
     * Required min RX interval: minimum interval, in microseconds, between received BFD Control packets 
     * that this system is capable of supporting, less any jitter applied by the sender (see section 6.8.2).
     * If this value is zero, the transmitting system does not want the remote system to send any periodic 
     * BFD Control packets.
     */
    packet->req_min_rx_interval = htonl(req_min_rx_interval);

    /* Required min echo RX interval, in microseconds  - always 0, echo mode currently not supported */
    packet->req_min_echo_rx_interval = 0;
}