/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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

#include "monkey.h"
#include "config.h"
#include "request.h"
#include "memory.h"
#include "iov.h"
#include "socket.h"
#include "epoll.h"
#include "http_status.h"
#include "utils.h"
#include "list.h"

#ifndef MK_PLUGIN_H
#define MK_PLUGIN_H

#define MK_PLUGIN_LOAD "plugins.load"

#define MK_PLUGIN_ERROR -1      /* plugin execution error */
#define MK_PLUGIN_

/* Plugin: Core types */
#define MK_PLUGIN_CORE_PRCTX (1)
#define MK_PLUGIN_CORE_THCTX (2)

/* Plugin: Stages */
#define MK_PLUGIN_STAGE_10 (4)     /* Connection just accept()ed */
#define MK_PLUGIN_STAGE_20 (8)     /* HTTP Request arrived */
#define MK_PLUGIN_STAGE_30 (16)     /* Object handler  */
#define MK_PLUGIN_STAGE_40 (32)    /* Content served */
#define MK_PLUGIN_STAGE_50 (64)    /* Conection ended */

/* Plugin: Network type */
#define MK_PLUGIN_NETWORK_IO (128)
#define MK_PLUGIN_NETWORK_IP (256)

/* Return values */
#define MK_PLUGIN_RET_NOT_ME -1
#define MK_PLUGIN_RET_CONTINUE 100
#define MK_PLUGIN_RET_END 200
#define MK_PLUGIN_RET_CLOSE_CONX 300

/* Event return values */
#define MK_PLUGIN_RET_EVENT_NOT_ME -300

/* NEW PROPOSAL */
struct plugin_core
{
    int (*prctx) ();
    int (*thctx) ();
};

struct plugin_stage
{
    int (*s10) (int, struct sched_connection *);
    int (*s20) (struct client_request *, struct request *);
    int (*s30) (struct plugin *, struct client_request *, struct request *);
    int (*s40) (struct client_request *, struct request *);
    int (*s50) (int);
};

struct plugin_network_io
{
    int (*accept) (int, struct sockaddr_in);
    int (*read) (int, void *, int);
    int (*write) (int, const void *, size_t);
    int (*writev) (int, struct mk_iov *);
    int (*close) (int);
    int (*connect) (int, char *, int);
    int (*send_file) (int, int, off_t *, size_t);
    int (*create_socket) (int, int, int);
    int (*bind) (int, const struct sockaddr *addr, socklen_t, int);
    int (*server) (int, char *);
};

struct plugin_network_ip
{
    int (*addr) (int);
    int (*maxlen) ();
};

struct plugin
{
    char *shortname;
    char *name;
    char *version;
    char *path;
    void *handler;
    int *hooks;

    /* Mandatory calls */
    int (*init) (void *, char *);
    int  (*exit) ();

    /* Hook functions by type */
    struct plugin_core core;
    struct plugin_stage stage;
    struct plugin_network_io net_io;
    struct plugin_network_ip net_ip;

    /* Epoll Events */
    int (*event_read) (int);
    int (*event_write) (int);
    int (*event_error) (int);
    int (*event_close) (int);
    int (*event_timeout) (int);

    /* Each plugin has a thread key for it's global data */
    pthread_key_t *thread_key;

    /* Next! */
    struct plugin *next;
};


/* Multiple plugins can work on multiple stages, we don't want
 * Monkey be comparing each plugin looking for a specific stage, 
 * so we create a Map of direct stage calls
 */
struct plugin_stagem
{
    struct plugin *p;
    struct plugin_stagem *next;
};

struct plugin_stagemap
{
    struct plugin_stagem *stage_10;
    struct plugin_stagem *stage_20;
    struct plugin_stagem *stage_30;
    struct plugin_stagem *stage_40;
    struct plugin_stagem *stage_50;
};

struct plugin_stagemap *plg_stagemap;

/* Network map calls */
struct plugin_network_io *plg_netiomap;
struct plugin_network_ip *plg_netipmap;

/* API functions exported to plugins */
struct plugin_api
{
    struct server_config *config;
    struct plugin *plugins;
    struct sched_list_node **sched_list;

    /* HTTP request function */
    int *(*http_request_end) (int);

    /* memory functions */
    void *(*mem_alloc) (int);
    void *(*mem_alloc_z) (int);
    void (*mem_free) (void *);
    void (*pointer_set) (mk_pointer *, char *);
    void (*pointer_print) (mk_pointer);

    /* string functions */
    char *(*str_build) (char **, unsigned long *, const char *, ...);
    char *(*str_dup) (const char *);
    int (*str_search) (char *, char *);
    int (*str_search_n) (char *, char *, int);
    char *(*str_copy_substr) (const char *, int, int);
    int (*str_itop) (int, mk_pointer *);
    struct mk_string_line *(*str_split_line) (const char *);

    /* file functions */
    char *(*file_to_buffer) (char *);
    struct file_info *(*file_get_info) (char *);
    int (*header_send) (int,
                          struct client_request *, struct request *);
    void (*header_set_http_status) (struct request *, int);

    /* iov functions */
    struct mk_iov *(*iov_create) (int, int);
    void (*iov_free) (struct mk_iov *);
    int (*iov_add_entry) (struct mk_iov *, char *, int, mk_pointer, int);
    int (*iov_set_entry) (struct mk_iov *, char *, int, int, int);
    ssize_t (*iov_send) (int, struct mk_iov *, int);
    void (*iov_print) (struct mk_iov *);

    /* plugin functions */
    void *(*plugin_load_symbol) (void *, char *);

    /* epoll functions */
    int (*epoll_create) (int);
    void *(*epoll_init) (int, mk_epoll_handlers *, int);
    int (*epoll_add) (int, int, int, int);
    int (*epoll_del) (int, int);
    int (*epoll_change_mode) (int, int, int);

    /* socket functions */
    int (*socket_cork_flag) (int, int);
    int (*socket_reset) (int);
    int (*socket_set_tcp_nodelay) (int);
    int (*socket_connect) (int, char *, int);
    int (*socket_set_nonblocking) (int);
    int (*socket_create) ();
    int (*socket_close) (int);
    int (*socket_sendv) (int, struct mk_iov *, int);
    int (*socket_send) (int, const void *, size_t);
    int (*socket_read) (int, void *, int);
    int (*socket_send_file) (int, int, off_t, size_t);

    /* configuration reader functions */
    struct mk_config *(*config_create) (char *);
    void (*config_free) (struct mk_config *);
    struct mk_config_section *(*config_section_get) (struct mk_config *,
                                                     char *);
    void *(*config_section_getval) (struct mk_config_section *, char *, int);
    struct sched_connection *(*sched_get_connection) (struct sched_list_node *,
                                                      int);

    /* worker's functions */
    int (*worker_spawn) (void (*func) (void *));

    /* event's functions */
    int (*event_add) (int, int, struct plugin *, struct client_request *, 
                      struct request *);
    int (*event_del) (int);

    int (*event_socket_change_mode) (int, int);

    /* system specific functions */
    int (*sys_get_somaxconn)();

    /* Time utils functions */
    int (*time_unix)();
    mk_pointer *(*time_human)();

#ifdef TRACE
    void (*trace)();
#endif

};

typedef char mk_plugin_data_t[];
typedef int mk_plugin_hook_t;
typedef pthread_key_t mk_plugin_key_t;

/* Plugin events thread key */
pthread_key_t mk_plugin_event_k;

struct plugin_event {
    int socket;

    struct plugin *handler;
    struct client_request *cr;
    struct request *sr;

    struct plugin_event *next;
};

void mk_plugin_init();
int mk_plugin_stage_run(mk_plugin_hook_t stage,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct client_request *cr, struct request *sr);

void mk_plugin_core_process();
void mk_plugin_core_thread();

void mk_plugin_request_handler_add(struct request *sr, struct plugin *p);
void mk_plugin_request_handler_del(struct request *sr, struct plugin *p);

void mk_plugin_preworker_calls();

/* Plugins events interface */
int mk_plugin_event_add(int socket, int mode,
                        struct plugin *handler,
                        struct client_request *cr, 
                        struct request *sr);
int mk_plugin_event_del(int socket);

int mk_plugin_event_set_list(struct plugin_event *event);
struct plugin_event *mk_plugin_event_get_list();
int mk_plugin_event_socket_change_mode(int socket, int mode);

/* Plugins event handlers */
int mk_plugin_event_read(int socket);
int mk_plugin_event_write(int socket);
int mk_plugin_event_error(int socket);
int mk_plugin_event_close(int socket);
int mk_plugin_event_timeout(int socket);

void mk_plugin_register_to(struct plugin **st, struct plugin *p);
void *mk_plugin_load_symbol(void *handler, const char *symbol);
int mk_plugin_http_request_end(int socket);

/* Register functions */
struct plugin *mk_plugin_register(struct plugin *p);
void mk_plugin_unregister(struct plugin *p);

struct plugin *mk_plugin_alloc(void *handler, char *path);
void mk_plugin_free(struct plugin *p);

int mk_plugin_time_now_unix();
mk_pointer *mk_plugin_time_now_human();

#endif
