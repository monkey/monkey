/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
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
#include "header.h"
#include "http_status.h"
#include "utils.h"
#include "str.h"
#include "list.h"
#include "info.h"

#ifndef MK_PLUGIN_H
#define MK_PLUGIN_H

#define MK_PLUGIN_LOAD "plugins.load"

#define MK_PLUGIN_ERROR -1      /* plugin execution error */
#define MK_PLUGIN_

/* Plugin: Core types */
#define MK_PLUGIN_CORE_PRCTX (1)
#define MK_PLUGIN_CORE_THCTX (2)

/* Plugin: Stages */
#define MK_PLUGIN_STAGE_10 (4)    /* Connection just accept()ed */
#define MK_PLUGIN_STAGE_20 (8)    /* HTTP Request arrived */
#define MK_PLUGIN_STAGE_30 (16)   /* Object handler  */
#define MK_PLUGIN_STAGE_40 (32)   /* Content served */
#define MK_PLUGIN_STAGE_50 (64)   /* Conection ended */

/* Plugin: Network type */
#define MK_PLUGIN_NETWORK_IO (128)
#define MK_PLUGIN_NETWORK_IP (256)

/* Return values */
#define MK_PLUGIN_RET_NOT_ME -1
#define MK_PLUGIN_RET_CONTINUE 100
#define MK_PLUGIN_RET_END 200
#define MK_PLUGIN_RET_CLOSE_CONX 300

/* 
 * Event return values
 * -------------------
 * Any plugin can hook to any socket event, when a worker thread receives
 * a socket event through epoll(), it will check first the plugins hooks
 * before return the control to Monkey core.
 */

 /* The plugin request to the caller to continue invoking next plugins */
#define MK_PLUGIN_RET_EVENT_NEXT -300

/* The plugin has taken some action and no other plugin should go
 * over the event in question, return as soon as possible
 */
#define MK_PLUGIN_RET_EVENT_OWNED -400

/* The plugin request to finalize the session request */
#define MK_PLUGIN_RET_EVENT_CLOSE -500

/* The plugin request to the caller skip event hooks */
#define MK_PLUGIN_RET_EVENT_CONTINUE -600

/* Contexts: process/thread */
struct plugin_core
{
    int (*prctx) ();
    int (*thctx) ();
};

struct plugin_stage
{
    int (*s10) (int, struct sched_connection *);
    int (*s20) (struct client_session *, struct session_request *);
    int (*s30) (struct plugin *, struct client_session *, struct session_request *);
    int (*s40) (struct client_session *, struct session_request *);
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
    unsigned int hooks;

    /* Mandatory calls */
    int (*init) (void *, char *);
    int  (*exit) ();

    /* Hook functions by type */
    struct plugin_core core;
    struct plugin_stage stage;
    struct plugin_network_io net_io;

    /* Epoll Events */
    int (*event_read) (int);
    int (*event_write) (int);
    int (*event_error) (int);
    int (*event_close) (int);
    int (*event_timeout) (int);

    /* Each plugin has a thread key for it's global data */
    pthread_key_t *thread_key;

    /* Next! */
    struct mk_list _head;
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
    struct plugin_stagem *stage_15;
    struct plugin_stagem *stage_20;
    struct plugin_stagem *stage_30;
    struct plugin_stagem *stage_40;
    struct plugin_stagem *stage_50;
};

struct plugin_stagemap *plg_stagemap;

/* Network map calls */
struct plugin_network_io *plg_netiomap;

/* API functions exported to plugins */
struct plugin_api
{
    struct server_config *config;
    struct mk_list *plugins;
    struct mk_list **sched_list;

    /* Error helper */
    int *(*_error) (int, const char *, ...);

    /* HTTP request function */
    int *(*http_request_end) (int);

    /* memory functions */
    void *(*mem_alloc) (int);
    void *(*mem_alloc_z) (int);
    void  (*mem_free) (void *);
    void  (*pointer_set) (mk_pointer *, char *);
    void  (*pointer_print) (mk_pointer);

    /* string functions */
    int   (*str_itop) (int, mk_pointer *);
    int   (*str_search) (const char *, const char *, int);
    int   (*str_search_n) (const char *, const char *, int, int);
    char *(*str_build) (char **, unsigned long *, const char *, ...);
    char *(*str_dup) (const char *);
    char *(*str_copy_substr) (const char *, int, int);
    struct mk_string_line *(*str_split_line) (const char *);

    /* file functions */
    char *(*file_to_buffer) (char *);
    struct file_info *(*file_get_info) (char *);

    /* header */
    int  (*header_send) (int, struct client_session *, struct session_request *);
    mk_pointer (*header_get) (struct header_toc *, mk_pointer);
    int  (*header_add) (struct session_request *, char *row, int len);
    void (*header_set_http_status) (struct session_request *, int);
    
    /* iov functions */
    struct mk_iov *(*iov_create) (int, int);
    void (*iov_free) (struct mk_iov *);
    int (*iov_add_entry) (struct mk_iov *, char *, int, mk_pointer, int);
    int (*iov_set_entry) (struct mk_iov *, char *, int, int, int);
    ssize_t (*iov_send) (int, struct mk_iov *);
    void (*iov_print) (struct mk_iov *);

    /* plugin functions */
    void *(*plugin_load_symbol) (void *, char *);

    /* epoll functions */
    void *(*epoll_init) (int, mk_epoll_handlers *, int);
    int   (*epoll_create) (int);
    int   (*epoll_add) (int, int, int, int);
    int   (*epoll_del) (int, int);
    int   (*epoll_change_mode) (int, int, int);

    /* socket functions */
    int (*socket_cork_flag) (int, int);
    int (*socket_reset) (int);
    int (*socket_set_tcp_nodelay) (int);
    int (*socket_connect) (int, char *, int);
    int (*socket_set_nonblocking) (int);
    int (*socket_create) ();
    int (*socket_close) (int);
    int (*socket_sendv) (int, struct mk_iov *);
    int (*socket_send) (int, const void *, size_t);
    int (*socket_read) (int, void *, int);
    int (*socket_send_file) (int, int, off_t, size_t);

    /* configuration reader functions */
    struct mk_config *(*config_create) (char *);
    void (*config_free) (struct mk_config *);
    struct mk_config_section *(*config_section_get) (struct mk_config *,
                                                     char *);
    void *(*config_section_getval) (struct mk_config_section *, char *, int);


    /* Scheduler */
    int (*sched_remove_client) (int);
    struct sched_connection *(*sched_get_connection) (struct sched_list_node *,
                                                      int);

    /* worker's functions */
    int (*worker_spawn) (void (*func) (void *));

    /* event's functions */
    int (*event_add) (int, int, struct plugin *, struct client_session *, 
                      struct session_request *);
    int (*event_del) (int);

    int (*event_socket_change_mode) (int, int);

    /* system specific functions */
    int (*sys_get_somaxconn)();

    /* Time utils functions */
    int (*time_unix)();
    mk_pointer *(*time_human)();

#ifdef TRACE
    void (*trace)();
    int (*errno_print) (int);
#endif

};

typedef pthread_key_t mk_plugin_key_t;

/* Plugin events thread key */
pthread_key_t mk_plugin_event_k;

struct plugin_event 
{
    int socket;
    
    struct plugin *handler;
    struct client_session *cs;
    struct session_request *sr;

    struct mk_list _head;
};

struct plugin_info {
    const char *shortname;
    const char *name;
    const char *version;
    unsigned int hooks;
};

void mk_plugin_init();
void mk_plugin_exit_all();

void mk_plugin_event_init_list();

int mk_plugin_stage_run(unsigned int stage,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct client_session *cs, struct session_request *sr);

void mk_plugin_core_process();
void mk_plugin_core_thread();

void mk_plugin_request_handler_add(struct session_request *sr, struct plugin *p);
void mk_plugin_request_handler_del(struct session_request *sr, struct plugin *p);

void mk_plugin_preworker_calls();

/* Plugins events interface */
int mk_plugin_event_add(int socket, int mode,
                        struct plugin *handler,
                        struct client_session *cs, 
                        struct session_request *sr);
int mk_plugin_event_del(int socket);

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

int mk_plugin_sched_remove_client(int socket);

int mk_plugin_header_add(struct session_request *sr, char *row, int len);
int mk_plugin_header_get(struct session_request *sr, 
                         mk_pointer query,
                         mk_pointer *result);

#endif
