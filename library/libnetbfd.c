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

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <libnet.h>

#include "../include/libnetbfd.h"
#include "../include/bfd_packet.h"
#include "../include/bfd_session.h"

/* Globals */
struct bfd_session_node *head = NULL;
pthread_rwlock_t read_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t write_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Prototypes */
static struct bfd_session_node *bfd_find_session_in_list(bfd_session_id session_id);

void bfd_session_change_param(bfd_session_id session_id, enum bfd_param param, uint32_t new_value)
{
    /* Find the session that we're interested in */
    pthread_rwlock_wrlock(&write_lock);
    struct bfd_session_node *session = bfd_find_session_in_list(session_id);

    if (session == NULL) {
        bfd_pr_error(NULL, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&write_lock);
        return;
    }

    switch (param) {

        case PARAM_DSCP:

            session->session_params->dscp = new_value;
            pthread_rwlock_unlock(&write_lock);

            break;

        case PARAM_DETECT_MULT:

            session->session_params->detect_mult = new_value;
            pthread_rwlock_unlock(&write_lock);

            break;

        default:
            bfd_pr_error(session->session_params->log_file, "Invalid bfd_session_change_param command.\n");
            pthread_rwlock_unlock(&write_lock);
            break;
    }
}

void bfd_session_modify(bfd_session_id session_id, enum bfd_modify_cmd cmd,
    uint32_t des_min_tx_interval, uint32_t req_min_rx_interval)
{
    pthread_rwlock_wrlock(&write_lock);
    struct bfd_session_node *session = bfd_find_session_in_list(session_id);

    if (session == NULL) {
        bfd_pr_error(NULL, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&write_lock);
        return;
    }

    struct cb_status *sess_cb_status = session->current_session->curr_sess_cb_status;

    switch (cmd) {
        case SESSION_ENABLE_ADMIN_DOWN:

            if (session->current_session->local_state != BFD_STATE_ADMIN_DOWN) {
                bfd_pr_debug(session->session_params->log_file, "Putting session: %ld into ADMIN_DOWN.\n", session_id);

                /* Save the current diag code */
                session->current_session->prev_bfd_diag = session->current_session->local_diag;

                /* Adjust state/diag/calback code for ADMIN_DOWN */
                session->current_session->local_state = BFD_STATE_ADMIN_DOWN;
                session->current_session->local_diag = BFD_DIAG_ADMIN_DOWN;
                sess_cb_status->cb_ret = BFD_CB_SESSION_ENABLE_ADMIN_DOWN;

                if (session->session_params->callback != NULL) {
                    session->session_params->callback(sess_cb_status);
                }
            }
            else
                bfd_pr_error(session->session_params->log_file, "Session: %ld is already in ADMIN_DOWN, skipping.\n", session_id);

            pthread_rwlock_unlock(&write_lock);

            break;

        case SESSION_DISABLE_ADMIN_DOWN:

            if (session->current_session->local_state == BFD_STATE_ADMIN_DOWN) {
                bfd_pr_debug(session->session_params->log_file, "Getting session: %ld out of ADMIN_DOWN.\n", session_id);

                /* Restore previous diag code */
                session->current_session->local_diag = session->current_session->prev_bfd_diag;

                /* Adjust state/callback for getting out of ADMIN_DOWN */
                session->current_session->local_state = BFD_STATE_DOWN;
                sess_cb_status->cb_ret = BFD_CB_SESSION_DISABLE_ADMIN_DOWN;

                if (session->session_params->callback != NULL) {
                    session->session_params->callback(sess_cb_status);
                }
            }
            else
                bfd_pr_error(session->session_params->log_file, "Session: %ld was not in ADMIN_DOWN, skipping.\n", session_id);

            pthread_rwlock_unlock(&write_lock);

            break;

        case SESSION_CHANGE_BFD_INTERVALS:

            if (des_min_tx_interval == 0 && req_min_rx_interval == 0) {
                bfd_pr_error(session->session_params->log_file, "Both parameters are 0, nothing to be done.\n");
                pthread_rwlock_unlock(&write_lock);
                return;
            }

            bfd_pr_debug(session->session_params->log_file, "BFD interval change requested for session [%s <--> %s], initiating Poll Sequence.\n", session->session_params->src_ip, session->session_params->dst_ip);

            /* Is it a good idea to change both of them at the same time? Time(testing) will tell */
            if (des_min_tx_interval > 0)
                session->session_params->des_min_tx_interval = des_min_tx_interval;

            if (req_min_rx_interval > 0)
                session->session_params->req_min_rx_interval = req_min_rx_interval;

            session->current_session->poll_in_progress = true;

            pthread_rwlock_unlock(&write_lock);

            break;

        default:
            bfd_pr_error(session->session_params->log_file, "Invalid bfd_session_modify command.\n");
            pthread_rwlock_unlock(&write_lock);
            break;
    }
}

const char *bfd_state2string(enum bfd_state state)
{
    switch(state) {
        case BFD_STATE_UP:
            return "BFD_STATE_UP";
        case BFD_STATE_DOWN:
            return "BFD_STATE_DOWN";
        case BFD_STATE_INIT:
            return "BFD_STATE_INIT";
        case BFD_STATE_ADMIN_DOWN:
            return "BFD_STATE_ADMIN_DOWN";
    }

    return "UNKNOWN BFD STATE";
}

const char *bfd_diag2string(enum bfd_diag diag)
{
    switch(diag) {
        case BFD_DIAG_NODIAG:
            return "BFD_DIAG_NODIAG";
        case BFD_DIAG_CTRL_DETECT_TIME_EXPIRED:
            return "BFD_DIAG_CTRL_DETECT_TIME_EXPIRED";
        case BFD_DIAG_ECHO_FUNCT_FAIL:
            return "BFD_DIAG_ECHO_FUNCT_FAIL";
        case BFD_DIAG_NEIGH_SIGNL_SESS_DOWN:
            return "BFD_DIAG_NEIGH_SIGNL_SESS_DOWN";
        case BFD_DIAG_FWD_PLANE_RESET:
            return "BFD_DIAG_FWD_PLANE_RESET";
        case BFD_DIAG_PATH_DOWN:
            return "BFD_DIAG_PATH_DOWN";
        case BFD_DIAG_CONCAT_PATH_DOWN:
            return "BFD_DIAG_CONCAT_PATH_DOWN";
        case BFD_DIAG_ADMIN_DOWN:
            return "BFD_DIAG_ADMIN_DOWN";
        case BFD_DIAG_REV_CONCAT_PATH_DOWN:
            return "BFD_DIAG_REV_CONCAT_PATH_DOWN";
    }

    return "UNKNOWN BFD DIAG";
}

static struct bfd_session_node *bfd_find_session_in_list(bfd_session_id session_id)
{
    struct bfd_session_node *it = head;

    while (it != NULL) {
        if (it->current_session->session_id == session_id)
            return it;
        it = it->next;
    }

    return NULL;
}

void bfd_session_print_stats(bfd_session_id session_id)
{
    time_t now;
    struct tm *local = NULL;
    char timestamp[100];

    pthread_rwlock_rdlock(&read_lock);
    struct bfd_session_node *session = bfd_find_session_in_list(session_id);

    if (session == NULL) {
        bfd_pr_error(NULL, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&read_lock);
        return;
    }

    /* Get and format timestamp */
    now = time(NULL);
    local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%d-%b-%Y %H:%M:%S", local);

    printf("---------------------------------------------\n");
    printf("%-25s %s\n", "Timestamp:", timestamp);
    printf("%-25s %ld\n", "Session ID:", session->current_session->session_id);
    if (strlen(session->session_params->net_ns))
        printf("%-25s %s\n", "Network namespace:", session->session_params->net_ns);
    printf("%-25s %s\n", "Source IP:", session->session_params->src_ip);
    printf("%-25s %s\n", "Destination IP:", session->session_params->dst_ip);
    printf("%-25s %d\n", "Source port:", session->current_session->src_port);
    printf("%-25s %d\n", "Destination port:", session->current_session->dst_port);
    printf("%-25s %s\n", "Device:", session->current_session->if_name);
    printf("%-25s %d\n", "DSCP:", session->session_params->dscp);
    printf("%-25s %d\n", "Des min TX interval:", session->current_session->des_min_tx_interval);
    printf("%-25s %d\n", "Req min RX interval:", session->current_session->req_min_rx_interval);
    printf("%-25s %d\n", "Detection Multiplier:", session->session_params->detect_mult);
    printf("%-25s 0x%x\n", "My discriminator:", session->current_session->local_discr);
    printf("%-25s %s\n", "Current state:", bfd_state2string(session->current_session->local_state));
    printf("%-25s %d\n", "Operational TX:", session->current_session->op_tx);
    printf("%-25s %lu\n", "Detection time:", session->current_session->detection_time);
#ifdef DEBUG_ENABLE
    printf("%-25s %p\n", "[DEBUG] TX timer id:", session->current_session->session_timer->timer_id);
#endif
    printf("---------------------------------------------\n");

    pthread_rwlock_unlock(&read_lock);
}

void bfd_session_print_stats_log(bfd_session_id session_id)
{
    time_t now;
    struct tm *local = NULL;
    char timestamp[100];
    FILE *file = NULL;

    pthread_rwlock_rdlock(&read_lock);
    struct bfd_session_node *session = bfd_find_session_in_list(session_id);

    if (session == NULL) {
        bfd_pr_error(NULL, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&read_lock);
        return;
    }

    /* Open log file */
    if (strlen(session->session_params->log_file) == 0) {
        pthread_rwlock_unlock(&read_lock);
        return;
    } else {
        file = fopen(session->session_params->log_file, "a");

        if (file == NULL) {
            bfd_pr_error(NULL, "Cannot open log file.\n");
            pthread_rwlock_unlock(&read_lock);
            return;
        }
    }

    /* Get and format timestamp */
    now = time(NULL);
    local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%d-%b-%Y %H:%M:%S", local);

    fprintf(file, "---------------------------------------------\n");
    fprintf(file, "%-25s %s\n", "Timestamp:", timestamp);
    fprintf(file, "%-25s %ld\n", "Session ID:", session->current_session->session_id);
    if (strlen(session->session_params->net_ns))
        fprintf(file, "%-25s %s\n", "Network namespace:", session->session_params->net_ns);
    fprintf(file, "%-25s %s\n", "Source IP:", session->session_params->src_ip);
    fprintf(file, "%-25s %s\n", "Destination IP:", session->session_params->dst_ip);
    fprintf(file, "%-25s %d\n", "Source port:", session->current_session->src_port);
    fprintf(file, "%-25s %d\n", "Destination port:", session->current_session->dst_port);
    fprintf(file, "%-25s %s\n", "Device:", session->current_session->if_name);
    fprintf(file, "%-25s %d\n", "DSCP:", session->session_params->dscp);
    fprintf(file, "%-25s %d\n", "Des min TX interval:", session->current_session->des_min_tx_interval);
    fprintf(file, "%-25s %d\n", "Req min RX interval:", session->current_session->req_min_rx_interval);
    fprintf(file, "%-25s %d\n", "Detection Multiplier:", session->session_params->detect_mult);
    fprintf(file, "%-25s 0x%x\n", "My discriminator:", session->current_session->local_discr);
    fprintf(file, "%-25s %s\n", "Current state:", bfd_state2string(session->current_session->local_state));
    fprintf(file, "%-25s %d\n", "Operational TX:", session->current_session->op_tx);
    fprintf(file, "%-25s %lu\n", "Detection time:", session->current_session->detection_time);
    fprintf(file, "---------------------------------------------\n");
    fclose(file);

    pthread_rwlock_unlock(&read_lock);
}

/* Return library version */
const char *netbfd_lib_version(void)
{
    return ("libnetbfd version "LIBNETBFD_VERSION);
}

void bfd_pr_log(char *log_file, const char *format, ...)
{
    va_list arg;
    time_t now;
    struct tm *local = NULL;
    char timestamp[100];
    FILE *file = NULL;

    if (log_file == NULL)
        return;

    if (strlen(log_file) == 0)
        return;
    else {
        file = fopen(log_file, "a");

        if (file == NULL) {
            perror("Error opening log file");
            return;
        }
    }

    va_start(arg, format);
    now = time(NULL);
    local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%d-%b-%Y %H:%M:%S", local);
    fprintf(file, "[%s] ", timestamp);
    vfprintf(file, format, arg);
    va_end(arg);
    fclose(file);
}

int bfd_session_get_local_diag(bfd_session_id session_id)
{
    pthread_rwlock_rdlock(&read_lock);
    struct bfd_session_node *session = bfd_find_session_in_list(session_id);

    if (session == NULL) {
        bfd_pr_error(NULL, "Could not find a valid BFD session with that id.\n");
        pthread_rwlock_unlock(&read_lock);
        return -1;
    }

    pthread_rwlock_unlock(&read_lock);

    return session->current_session->local_diag;
}
