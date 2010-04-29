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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <err.h>

#include "config.h"
#include "plugin.h"
#include "monkey.h"
#include "request.h"
#include "scheduler.h"
#include "utils.h"
#include "str.h"
#include "file.h"
#include "header.h"
#include "memory.h"
#include "iov.h"
#include "epoll.h"

void *mk_plugin_load(char *path)
{
    void *handle;

    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error during dlopen(): %s\n", dlerror());
        exit(1);
    }
    return handle;
}

void *mk_plugin_load_symbol(void *handler, const char *symbol)
{
    char *err;
    void *s;

    dlerror();
    s = dlsym(handler, symbol);
    if ((err = dlerror()) != NULL) {
        return NULL;
    }

    return s;
}

void mk_plugin_register_stagemap_add(struct plugin_stagem **stm, struct plugin *p)
{
    struct plugin_stagem *list, *new;

    new = mk_mem_malloc_z(sizeof(struct plugin_stagem));
    new->p = p;
    new->next = NULL;

    if (!*stm) {
        *stm = new;
        return;
    }

    list = *stm;

    while (list->next) {
        list = list->next;
    }

    list->next = new;
}

void mk_plugin_register_stagemap(struct plugin *p)
{
    /* Plugin to stages */
    if (*p->hooks & MK_PLUGIN_STAGE_10) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_10, p);
    }

    if (*p->hooks & MK_PLUGIN_STAGE_20) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_20, p);
    }

    if (*p->hooks & MK_PLUGIN_STAGE_30) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_30, p);
    }

    if (*p->hooks & MK_PLUGIN_STAGE_40) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_40, p);
    }

    if (*p->hooks & MK_PLUGIN_STAGE_50) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_50, p);
    }
}

/* Load the plugins and set the library symbols to the
 * local struct plugin *p node
 */
struct plugin *mk_plugin_register(void *handler, char *path)
{
    struct plugin *p;

    p = mk_mem_malloc_z(sizeof(struct plugin));
    p->shortname = mk_plugin_load_symbol(handler, "_shortname");
    p->name = mk_plugin_load_symbol(handler, "_name");
    p->version = mk_plugin_load_symbol(handler, "_version");
    p->path = mk_string_dup(path);
    p->handler = handler;
    p->hooks =
        (mk_plugin_hook_t *) mk_plugin_load_symbol(handler, "_hooks");

    /* Mandatory functions */
    p->init = (int (*)()) mk_plugin_load_symbol(handler, "_mkp_init");
    p->exit = (int (*)()) mk_plugin_load_symbol(handler, "_mkp_exit");

    /* Core hooks */
    p->core.prctx = (int (*)()) mk_plugin_load_symbol(handler,
                                                      "_mkp_core_prctx()");
    p->core.thctx = (int (*)()) mk_plugin_load_symbol(handler,
                                                      "_mkp_core_thctx()");

    /* Stage hooks */
    p->stage.s10 = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_stage_10");

    p->stage.s20 = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_stage_20");

    p->stage.s30 = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_stage_30");

    p->stage.s40 = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_stage_40");

    p->stage.s50 = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_stage_50");

    /* Network I/O hooks */
    p->net_io.accept = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_accept");

    p->net_io.read = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_read");

    p->net_io.write = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_write");

    p->net_io.writev = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_writev");

    p->net_io.close = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_close");

    p->net_io.connect = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_connect");

    p->net_io.send_file = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_send_file");

    p->net_io.create_socket = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_create_socket");

    p->net_io.bind = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_bind");

    p->net_io.server = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_io_server");


    /* Network IP hooks */
    p->net_ip.addr = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_ip_addr");

    p->net_ip.maxlen = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_network_ip_maxlen");

    /* Thread key */
    p->thread_key = (pthread_key_t) mk_plugin_load_symbol(handler,
                                                          "_mkp_data");

    /* Event handlers hooks */
    p->event_read = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_event_read");

    p->event_write = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_event_write");

    p->event_error = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_event_error");

    p->event_close = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_event_close");

    p->event_timeout = (int (*)())
        mk_plugin_load_symbol(handler, "_mkp_event_timeout");

    /* Next ! */
    p->next = NULL;

    if (!p->name || !p->version || !p->hooks) {
#ifdef TRACE
        MK_TRACE("Bad plugin definition: %s", path);
#endif
        mk_mem_free(p->path);
        mk_mem_free(p);
        return NULL;
    }

    /* NETWORK_IO Plugin */
    if (*p->hooks & MK_PLUGIN_NETWORK_IO) {
        /* Validate mandatory calls */
        if (!p->net_io.accept || !p->net_io.read || !p->net_io.write ||
            !p->net_io.writev || !p->net_io.close || !p->net_io.connect ||
            !p->net_io.send_file || !p->net_io.create_socket || !p->net_io.bind ||
            !p->net_io.server ) {
#ifdef TRACE
                MK_TRACE("Networking IO plugin incomplete: %s", path);
                MK_TRACE("Mapped Functions\naccept : %p\nread : %p\n\
write : %p\nwritev: %p\nclose : %p\nconnect : %p\nsendfile : %p\n\
create socket : %p\nbind : %p\nserver : %p",
                         p->net_io.accept,
                         p->net_io.read,
                         p->net_io.write,
                         p->net_io.writev,
                         p->net_io.close,
                         p->net_io.connect,
                         p->net_io.send_file,
                         p->net_io.create_socket,
                         p->net_io.bind,
                         p->net_io.server);
#endif
                mk_mem_free(p->path);
                mk_mem_free(p);
                return NULL;
            }

        /* Restrict to one NETWORK_IO plugin */
        if (!plg_netiomap) {
            plg_netiomap = &p->net_io;
        }
        else {
            fprintf(stderr,
                    "\nError: Loading more than one Network IO Plugin: %s",
                    path);
            exit(1);
        }
    }

    /* NETWORK_IP Plugin */
    if (*p->hooks & MK_PLUGIN_NETWORK_IP) {
        /* Validate mandatory calls */
        if (!p->net_ip.addr || !p->net_ip.maxlen) {
#ifdef TRACE
            MK_TRACE("Networking IP plugin incomplete: %s", path);
            MK_TRACE("Mapped Functions\naddr   :%p\nmaxlen :%p",
                     p->net_ip.addr,
                     p->net_ip.maxlen);
#endif
            mk_mem_free(p->path);
            mk_mem_free(p);
            return NULL;
        }

        /* Restrict to one NETWORK_IP plugin */
        if (!plg_netipmap) {
            plg_netipmap = &p->net_ip;
        }
        else {
            fprintf(stderr,
                    "\nError: Loading more than one Network IP Plugin: %s",
                    path);
            exit(1);
        }
    }

    /* Add Plugin to the end of the list */
    if (!config->plugins) {
        config->plugins = p;
    }
    else {
        struct plugin *plg = config->plugins;
        while(plg->next){
            plg = plg->next;
        }
        plg->next = p;
    }

    mk_plugin_register_stagemap(p);
    return p;
}

void mk_plugin_init()
{
    char *path;
    void *handle;
    struct plugin *p;
    struct plugin_api *api;
    struct mk_config *cnf;

    api = mk_mem_malloc_z(sizeof(struct plugin_api));
    plg_stagemap = mk_mem_malloc_z(sizeof(struct plugin_stagemap));
    plg_netiomap = NULL;
    plg_netipmap = NULL;

    /* Setup and connections list */
    api->config = config;
    api->sched_list = &sched_list;

    /* API plugins funcions */
    /* Memory callbacks */
    api->pointer_set = (void *) mk_pointer_set;
    api->pointer_print = (void *) mk_pointer_print;
    api->plugin_load_symbol = (void *) mk_plugin_load_symbol;
    api->mem_alloc = (void *) mk_mem_malloc;
    api->mem_alloc_z = (void *) mk_mem_malloc_z;
    api->mem_free = (void *) mk_mem_free;
    /* String Callbacks */
    api->str_build = (void *) mk_string_build;
    api->str_dup = (void *) mk_string_dup;
    api->str_search = (void *) mk_string_search;
    api->str_search_n = (void *) mk_string_search_n;
    api->str_copy_substr = (void *) mk_string_copy_substr;
    api->str_split_line = (void *) mk_string_split_line;
    /* File Callbacks */
    api->file_to_buffer = (void *) mk_file_to_buffer;
    api->file_get_info = (void *) mk_file_get_info;
    /* HTTP Callbacks */
    api->header_send = (void *) mk_header_send;
    /* IOV callbacks */
    api->iov_create = (void *) mk_iov_create;
    api->iov_free = (void *) mk_iov_free;
    api->iov_add_entry = (void *) mk_iov_add_entry;
    api->iov_set_entry = (void *) mk_iov_set_entry;
    api->iov_send = (void *) mk_iov_send;
    api->iov_print = (void *) mk_iov_print;
    /* Socket callbacks */
    api->socket_cork_flag = (void *) mk_socket_set_cork_flag;
    api->socket_connect = (void *) mk_socket_connect;
    api->socket_reset = (void *) mk_socket_reset;
    api->socket_set_tcp_nodelay = (void *) mk_socket_set_tcp_nodelay;
    api->socket_set_nonblocking = (void *) mk_socket_set_nonblocking;
    api->socket_create = (void *) mk_socket_create;
    api->socket_close = (void *) mk_socket_close;
    api->socket_sendv = (void *) mk_socket_sendv;
    api->socket_send = (void *) mk_socket_send;
    api->socket_read = (void *) mk_socket_read;
    api->socket_send_file = (void *) mk_socket_send_file;
    /* Config Callbacks */
    api->config_create = (void *) mk_config_create;
    api->config_free = (void *) mk_config_free;
    api->config_getval = (void *) mk_config_getval;
    /* Scheduler and Event callbacks */
    api->sched_get_connection = (void *) mk_sched_get_connection;
    api->event_add = (void *) mk_plugin_event_add;
    api->event_socket_change_mode = (void *) mk_plugin_event_socket_change_mode;

    /* Some useful functions =) */
    api->sys_get_somaxconn = (void *) mk_utils_get_somaxconn;
#ifdef TRACE
    api->trace = (void *) mk_utils_trace;
#endif

    /* Read configuration file */
    path = mk_mem_malloc_z(1024);
    snprintf(path, 1024, "%s/%s", config->serverconf, MK_PLUGIN_LOAD);
    cnf = mk_config_create(path);

    while (cnf) {
        if (strcasecmp(cnf->key, "LoadPlugin") == 0) {
            handle = mk_plugin_load(cnf->val);
            p = mk_plugin_register(handle, cnf->val);
            if (!p) {
                fprintf(stderr, "Plugin error: %s\n", cnf->val);
                dlclose(handle);
            }
            else {
                char *plugin_confdir = 0;
                unsigned long len;

                mk_string_build(&plugin_confdir,
                                &len,
                                "%s/plugins/%s/",
                                config->serverconf, p->shortname);

                p->init(&api, plugin_confdir);
            }
        }
        cnf = cnf->next;
    }

    if (!plg_netiomap) {
        fprintf(stderr, "\nError: no Network plugin loaded >:|\n\n");
        exit(1);
    }

    api->plugins = config->plugins;
    mk_mem_free(path);
}

int mk_plugin_stage_run(mk_plugin_hook_t hook,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct client_request *cr, struct request *sr)
{
    int ret;
    struct plugin_stagem *stm;

    if (hook & MK_PLUGIN_STAGE_10) {
        stm = plg_stagemap->stage_10;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 10", stm->p->shortname);
#endif
            stm->p->stage.s10();
            stm = stm->next;
        }
    }

    if (hook & MK_PLUGIN_STAGE_20) {
        stm = plg_stagemap->stage_20;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 20", stm->p->shortname);
#endif
            ret = stm->p->stage.s20(socket, conx, cr);
            switch (ret) {
            case MK_PLUGIN_RET_CLOSE_CONX:
#ifdef TRACE
                MK_TRACE("return MK_PLUGIN_RET_CLOSE_CONX");
#endif
                return MK_PLUGIN_RET_CLOSE_CONX;
            }

            stm = stm->next;
        }
    }

    if (hook & MK_PLUGIN_STAGE_30) {
        stm = plg_stagemap->stage_30;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 30", stm->p->shortname);
#endif
            ret = stm->p->stage.s30(cr, sr);
            switch (ret) {
            case MK_PLUGIN_RET_CLOSE_CONX:
                return MK_PLUGIN_RET_CLOSE_CONX;
            }

            stm = stm->next;
        }
    }

    /* Object handler */
    if (hook & MK_PLUGIN_STAGE_40) {
        /* The request just arrived and is required to check who can
         * handle it */
        if (!sr->handled_by){
            stm = plg_stagemap->stage_40;
            while (stm) {
                /* Call stage */
#ifdef TRACE
                MK_TRACE("[%s] STAGE 40", stm->p->shortname);
#endif
                ret = stm->p->stage.s40(stm->p, cr, sr);

                switch (ret) {
                case MK_PLUGIN_RET_NOT_ME:
                    break;
                case MK_PLUGIN_RET_CONTINUE:
                    return MK_PLUGIN_RET_CONTINUE;
                }
                stm = stm->next;
            }
        }
    }

    if (hook & MK_PLUGIN_STAGE_50) {
        stm = plg_stagemap->stage_50;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 50", stm->p->shortname);
#endif
            ret = stm->p->stage.s50(cr, sr);
            switch (ret) {
            case MK_PLUGIN_RET_NOT_ME:
                break;
            case MK_PLUGIN_RET_CONTINUE:
                return MK_PLUGIN_RET_CONTINUE;
            }
            stm = stm->next;
        }
    }

    return -1;
}

void mk_plugin_request_handler_add(struct request *sr, struct plugin *p)
{
    if (!sr->handled_by) {
        sr->handled_by = p;
        return;
    }
}

void mk_plugin_request_handler_del(struct request *sr, struct plugin *p)
{
    if (!sr->handled_by) {
        return;
    }

    mk_mem_free(sr->handled_by);
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void mk_plugin_worker_startup()
{
    struct plugin *p;

    p = config->plugins;

    while (p) {
        /* Init plugin */
        if (p->core.thctx) {
            p->core.thctx();
        }

        p = p->next;
    }
}

/* This function is called by Monkey *outside* of the
 * thread context for plugins, so here's the right
 * place to set pthread keys or similar
 */
void mk_plugin_preworker_calls()
{
    int ret;
    struct plugin *p;

    p = config->plugins;

    while (p) {
        /* Init pthread keys */
        if (p->thread_key) {
            ret = pthread_key_create(&p->thread_key, NULL);
            if (ret != 0) {
                printf("\nPlugin Error: could not create key for %s",
                       p->shortname);
                fflush(stdout);
                exit(1);
            }
        }
        p = p->next;
    }
}

int mk_plugin_event_add(int socket, int mode,
                        struct plugin *handler,
                        struct client_request *cr,
                        struct request *sr)
{
    struct sched_list_node *sched;
    struct plugin_event *list;
    struct plugin_event *aux;
    struct plugin_event *event;

    sched = mk_sched_get_thread_conf();

    if (!sched || !handler || !cr || !sr) {
        return -1;
    }

    /* Event node (this list exist at thread level */
    event = mk_mem_malloc(sizeof(struct plugin_event));
    event->socket = socket;
    event->handler = handler;
    event->cr = cr;
    event->sr = sr;
    event->next = NULL;

    /* Get thread event list */
    list = mk_plugin_event_get_list();
    if (!list) {
        mk_plugin_event_set_list(event);
    }
    else {
        aux = list;
        while (aux->next) {
            aux = aux->next;
        }

        aux->next = event;
        mk_plugin_event_set_list(aux);
    }

    /* The thread event info has been registered, now we need
       to register the socket involved to the thread epoll array */
    mk_epoll_add(sched->epoll_fd, event->socket,
                 mode, MK_EPOLL_BEHAVIOR_DEFAULT);
    return 0;
}

int mk_plugin_event_socket_change_mode(int socket, int mode)
{
    struct sched_list_node *sched;

    sched = mk_sched_get_thread_conf();

    if (!sched) {
        return -1;
    }

    return mk_epoll_change_mode(sched->epoll_fd, socket, mode);
}

struct plugin_event *mk_plugin_event_get(int socket)
{
    struct plugin_event *event;

    event = mk_plugin_event_get_list();

    while (event){
        if (event->socket == socket) {
            return event;
        }

        event = event->next;
    }

    return NULL;
}

int mk_plugin_event_set_list(struct plugin_event *event)
{
    return pthread_setspecific(mk_plugin_event_k, (void *) event);
}

struct plugin_event *mk_plugin_event_get_list()
{
    return (struct plugin_event *) pthread_getspecific(mk_plugin_event_k);

}

/* Plugin epoll event handlers
 * ---------------------------
 * this functions are called by connection.c functions as mk_conn_read(),
 * mk_conn_write(),mk_conn_error(), mk_conn_close() and mk_conn_timeout
 *
 * Return Values:
 * -------------
 *    MK_PLUGIN_RET_EVENT_NOT_ME: There's no plugin hook associated
 */

int mk_plugin_event_read(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("Plugin, event read FD %i", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_read) {
        return event->handler->event_read(event->cr, event->sr);
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_write(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("Plugin, event write FD %i", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_write) {
        return event->handler->event_write(event->cr, event->sr);
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_error(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("Plugin, event error FD %i", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_error) {
        return event->handler->event_error(event->cr, event->sr);
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_close(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("Plugin, event close FD %i", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_close) {
        return event->handler->event_close(event->cr, event->sr);
    }

    return 0;
}

int mk_plugin_event_timeout(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("Plugin, event timeout FD %i", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_timeout) {
        return event->handler->event_timeout(event->cr, event->sr);
    }

    return 0;
}
