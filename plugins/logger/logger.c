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


#include "plugin.h"
#include "utils.h"
#include "logger.h"
#include "epoll.h"
#include "unistd.h"

/* Plugin data for register */
mk_plugin_data_t _shortname = "logger";
mk_plugin_data_t _name = "Logger";
mk_plugin_data_t _version = "0.11.0";
mk_plugin_hook_t _hooks = MK_PLUGIN_CORE_PRCTX | MK_PLUGIN_STAGE_40;

struct plugin_api *mk_api;

char *mk_logger_match(int fd)
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

    PLUGIN_TRACE("WORKER INIT!");

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
    buffer_limit = (pipe_size * MK_LOGFILE_PIPE_LIMIT);

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
    
    timeout = time(NULL) + MK_LOGFILE_TIMEOUT;

    /* Reading pipe buffer */
    while (1) {
        usleep(1200);

        PLUGIN_TRACE("PRE");
        struct epoll_event events[max_events];
        int num_fds = epoll_wait(efd, events, max_events, -1);

        /* fixme */
        //clk = log_current_utime;
        clk = time(NULL);

        for (i = 0; i < num_fds; i++) {
            target = mk_logger_match(events[i].data.fd);

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
                timeout = clk + MK_LOGFILE_TIMEOUT;
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
    mk_api = *api;
    return 0;
}

void _mkp_exit()
{
}

void _mkp_core_prctx()
{
    int i;

    struct log_target *new;
    struct host *host;
    struct mk_config_section *section;
    struct mk_config_entry *access_entry, *error_entry;

#ifdef TRACE
    PLUGIN_TRACE("Reading virtual host info");
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
                PLUGIN_TRACE("Linking Vhost %s", host->servername);
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
    i = mk_api->worker_spawn((void *) mk_logger_worker_init);
    PLUGIN_TRACE("CORE CTX!: %i", i);
}

int _mkp_stage_10(unsigned int socket, struct sched_connection *conx)
{
    printf("\n10) [socket %i] Llego una nueva conexión", socket);
    fflush(stdout);

    return MK_PLUGIN_RET_CONTINUE;
}

int _mkp_stage_20(struct client_request *cr, struct request *sr)
{
    printf("\n20) [socket %i] IP %s", cr->socket, cr->ipv4->data);
    fflush(stdout);

    return MK_PLUGIN_RET_CONTINUE;
}

int _mkp_stage_40(struct client_request *cr, struct request *sr)
{
    printf("\n40) [socket %i] Request finalizado", cr->socket);
    fflush(stdout);
    
    return 0;
}

