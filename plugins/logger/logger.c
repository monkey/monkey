/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include "http.h"
#include "plugin.h"
#include "utils.h"
#include "logger.h"
#include "pointers.h"
#include "http_status.h"
#include "epoll.h"

/* Plugin data for register */
mk_plugin_data_t _shortname = "logger";
mk_plugin_data_t _name = "Logger";
mk_plugin_data_t _version = "0.11.0";
mk_plugin_hook_t _hooks = MK_PLUGIN_CORE_PRCTX | 
                          MK_PLUGIN_CORE_THCTX | MK_PLUGIN_STAGE_40;

/* Thread key data */
mk_plugin_key_t _mkp_data;

char *mk_logger_match_by_fd(int fd)
{
    struct log_target *aux;

    aux = lt;

    while (aux) {
        if (aux->fd_access[0] == fd) {
            return aux->file_access;
        }
        if (aux->fd_error[0] == fd) {
            return aux->file_error;
        }
        aux = aux->next;
    }

    return NULL;
}

struct log_target *mk_logger_match_by_host(struct host *host)
{
    struct log_target *target;

    target = lt;
    while (target) {
        if (target->host == host) {
            return target;
        }
        target = target->next;
    }

    return NULL;
}

struct iov *mk_logger_get_cache()
{
    return pthread_getspecific(_mkp_data);
}

void *mk_logger_worker_init(void *args)
{
    int efd, max_events = mk_api->config->nhosts;
    int i, bytes, err;
    int flog;
    long slen;
    int timeout;
    int clk;
    char *target;
    struct log_target *lt_aux;

    /* pipe_size:
     * ---------- 
     * Linux set a pipe size usingto the PAGE_SIZE, 
     * check linux/include/pipe_fs_i.h for details:
     *
     *       #define PIPE_SIZE               PAGE_SIZE
     *
     * In the same header file we can found that every 
     * pipe has 16 pages, so our real memory allocation
     * is: (PAGE_SIZE*PIPE_BUFFERS)
     */
    long pipe_size;

    /* buffer_limit:
     * -------------
     * it means the maximum data that a monkey log pipe can contain.
     */
    long buffer_limit;

    /* Monkey allow just 75% of a pipe capacity */
    pipe_size = sysconf(_SC_PAGESIZE) * 16;
    buffer_limit = (pipe_size * MK_LOGGER_PIPE_LIMIT);

    /* Creating poll */
    efd = mk_api->epoll_create(max_events);

    lt_aux = lt;
    while (lt_aux) {
        /* Add access log file */
        if (lt_aux->fd_access[0] > 0) {
            mk_api->epoll_add(efd, lt_aux->fd_access[0], 
                              MK_EPOLL_READ, MK_EPOLL_BEHAVIOR_DEFAULT);
            //mk_logger_target_add(lt_aux->fd_access[0], h->access_log_path);
        }
        /* Add error log file */
        if (lt_aux->fd_error[0] > 0) {
            mk_api->epoll_add(efd, lt_aux->fd_error[0], 
                              MK_EPOLL_READ, MK_EPOLL_BEHAVIOR_DEFAULT);
            //mk_logger_target_add(h->log_error[0], h->error_log_path);
        }
        lt_aux = lt_aux->next;
    }
    
    timeout = time(NULL) + mk_logger_timeout;

    /* Reading pipe buffer */
    while (1) {
        usleep(1200);

        struct epoll_event events[max_events];
        int num_fds = epoll_wait(efd, events, max_events, -1);

        clk = mk_api->time_unix();

        for (i = 0; i < num_fds; i++) {
            target = mk_logger_match_by_fd(events[i].data.fd);

            if (!target) {
                printf("\nERROR matching host/epoll_fd");
                fflush(stdout);
                continue;
            }

            err = ioctl(events[i].data.fd, FIONREAD, &bytes);
            if (err == -1) {
                perror("ioctl");
            }

            if (bytes < buffer_limit && clk <= timeout) {
                break;
            }
            else {
                timeout = clk + mk_logger_timeout;
                flog = open(target, O_WRONLY | O_CREAT, 0644);

                if (flog == -1) {
                    printf("\n* error: check your logfile file permission");
                    perror("open");
                    continue;
                }

                lseek(flog, 0, SEEK_END);
                slen = splice(events[i].data.fd, NULL, flog,
                              NULL, bytes, SPLICE_F_MOVE);
                if (slen == -1) {
                    perror("splice");
                }
                close(flog);
            }
        }
    }
}

int _mkp_init(void **api, char *confdir)
{
    int timeout;
    struct mk_config_section *section;

    mk_api = *api;
    
    /* Global configuration */
    mk_logger_timeout = MK_LOGGER_TIMEOUT_DEFAULT;
    section = mk_api->config_section_get(mk_api->config->config, "LOGGER");
    if (section) {
        timeout = (int) mk_api->config_section_getval(section,
                                                      "FlushTimeout",
                                                      MK_CONFIG_VAL_NUM);
        if (timeout <= 0) {
            fprintf(stderr, 
                    "\nError: FlushTimeout does not have a proper value\n\n");
            exit(1);
        }
        mk_logger_timeout = timeout;
    }

    /* Init mk_pointers */
    mk_logger_init_pointers();

    return 0;
}

void _mkp_exit()
{
}

void _mkp_core_prctx()
{
    struct log_target *new;
    struct host *host;
    struct mk_config_section *section;
    struct mk_config_entry *access_entry, *error_entry;

#ifdef TRACE
    PLUGIN_TRACE("Reading virtual hosts");
#endif

    host = mk_api->config->hosts;
    while (host) {
        /* Read logger section from virtual host configuration */
        section = mk_api->config_section_get(host->config, "LOGGER");
        if (section) {
            /* Read configuration entries */
            access_entry = mk_api->config_section_getval(section, "AccessLog", 
                                                         MK_CONFIG_VAL_STR);
            error_entry = mk_api->config_section_getval(section, "ErrorLog",
                                                        MK_CONFIG_VAL_STR);

            if (access_entry || error_entry) {
                new = mk_api->mem_alloc(sizeof(struct log_target));
                /* Set access pipe */
                if (access_entry) {
                    if (pipe(new->fd_access) < 0) {
                        perror("pipe");
                        exit(1);
                    }
                    fcntl(new->fd_access[1], F_SETFL, O_NONBLOCK);
                    new->file_access = (char *) access_entry;
                }
                /* Set error pipe */
                if (error_entry) {
                    if (pipe(new->fd_error) < 0) {
                        perror("pipe");
                        exit(1);
                    }
                    fcntl(new->fd_error[1], F_SETFL, O_NONBLOCK);
                    new->file_error = (char *) error_entry;
                }

                new->host = host;
                new->next = NULL;

#ifdef TRACE
                PLUGIN_TRACE("Setting up vhost '%s'", host->servername);
#endif                
                /* Link node to main list */
                if (!lt) {
                    lt = new;
                }
                else {
                    struct log_target *aux;
                    aux = lt;
                    while (aux->next) {
                        aux = aux->next;
                    }
                    aux->next = new;
                }
                
            }
        }
        host = host->next;
    }
    
    mk_api->worker_spawn((void *) mk_logger_worker_init);
}

void _mkp_core_thctx()
{
    struct mk_iov *iov_log;

#ifdef TRACE
    PLUGIN_TRACE("Creating thread cache");
#endif
    
    /* Cache iov log struct */
    iov_log = mk_api->iov_create(15, 0);
    pthread_setspecific(_mkp_data, (void *) iov_log);
}

int _mkp_stage_40(struct client_request *cr, struct request *sr)
{
    int http_status;
    struct log_target *target;
    struct mk_iov *iov;
    mk_pointer *date;

    http_status = sr->headers->status;
 
    /* Look for target log file */
    target = mk_logger_match_by_host(sr->host_conf);
    if (!target) {
#ifdef TRACE
        PLUGIN_TRACE("No target found");
#endif
        return 0;
    }

    /* Get iov cache struct and reset indexes */
    iov = (struct mk_iov *) mk_logger_get_cache();
    iov->iov_idx = 0;
    iov->buf_idx = 0;
    iov->total_len = 0;

    /* IP */
    mk_api->iov_add_entry(iov, cr->ipv4->data, cr->ipv4->len,
                          mk_logger_iov_dash, MK_IOV_NOT_FREE_BUF);

    /* Date/time when object was requested */
    date = mk_api->time_human();
    mk_api->iov_add_entry(iov, date->data, date->len,
                          mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);

    /* Access Log */
    if (http_status < 400){
        /* No access file defined */
        if (!target->file_access) {
            return 0;
        }

        /* HTTP Method */
        mk_api->iov_add_entry(iov, 
                              sr->method_p.data, 
                              sr->method_p.len, 
                              mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);

        /* HTTP URI required */
        mk_api->iov_add_entry(iov, sr->uri.data, sr->uri.len,
                              mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);

        /* HTTP Protocol */
        mk_api->iov_add_entry(iov, sr->protocol_p.data, sr->protocol_p.len,
                              mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);

        /* HTTP Status code response */
        mk_api->iov_add_entry(iov, 
                              sr->headers->status_p->data,
                              sr->headers->status_p->len,
                              mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);

        /* Content Length */
        if (sr->method != HTTP_METHOD_HEAD) {
            mk_api->iov_add_entry(iov,
                                  sr->headers->content_length_p.data,
                                  sr->headers->content_length_p.len - 2, 
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
        }
        else {
            mk_api->iov_add_entry(iov,
                                  mk_logger_iov_empty.data,
                                  mk_logger_iov_empty.len, 
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
        }

        /* Write iov array to pipe */
        mk_api->iov_send(target->fd_access[1], iov, MK_IOV_SEND_TO_PIPE);
    }
    else {
        if (!target->file_error) {
            return 0;
        }
        switch (http_status) {
        case M_CLIENT_BAD_REQUEST:
            mk_api->iov_add_entry(iov,
                                  error_msg_400.data,
                                  error_msg_400.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        case M_CLIENT_FORBIDDEN:
            mk_api->iov_add_entry(iov,
                                  error_msg_403.data,
                                  error_msg_403.len,
                                  mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);
            mk_api->iov_add_entry(iov,
                                  sr->uri.data,
                                  sr->uri.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF)
            break;
        case M_CLIENT_NOT_FOUND:
            mk_api->iov_add_entry(iov,
                                  error_msg_404.data,
                                  error_msg_404.len,
                                  mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);
            mk_api->iov_add_entry(iov,
                                  sr->uri.data,
                                  sr->uri.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        case M_CLIENT_METHOD_NOT_ALLOWED:
            mk_api->iov_add_entry(iov,
                                  error_msg_405.data,
                                  error_msg_405.len,
                                  mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);
            mk_api->iov_add_entry(iov,
                                  sr->method_p.data,
                                  sr->method_p.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        case M_CLIENT_REQUEST_TIMEOUT:
            mk_api->iov_add_entry(iov,
                                  error_msg_408.data,
                                  error_msg_408.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        case M_CLIENT_LENGTH_REQUIRED:
            mk_api->iov_add_entry(iov,
                                  error_msg_411.data,
                                  error_msg_411.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        case M_SERVER_NOT_IMPLEMENTED:
            mk_api->iov_add_entry(iov,
                                  error_msg_501.data,
                                  error_msg_501.len,
                                  mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);

            mk_api->iov_add_entry(iov,
                                  sr->method_p.data,
                                  sr->method_p.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        case M_SERVER_INTERNAL_ERROR:
            mk_api->iov_add_entry(iov,
                                  error_msg_500.data,
                                  error_msg_500.len,
                                  mk_logger_iov_space, MK_IOV_NOT_FREE_BUF);
            break;
        case M_SERVER_HTTP_VERSION_UNSUP:
            mk_api->iov_add_entry(iov,
                                  error_msg_505.data,
                                  error_msg_505.len,
                                  mk_logger_iov_lf, MK_IOV_NOT_FREE_BUF);
            break;
        }
        /* Write iov array to pipe */
        mk_api->iov_send(target->fd_error[1], iov, MK_IOV_SEND_TO_PIPE);
    }


    return 0;
}
