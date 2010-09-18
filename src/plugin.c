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
#include "connection.h"
#include "plugin.h"
#include "monkey.h"
#include "request.h"
#include "scheduler.h"
#include "utils.h"
#include "str.h"
#include "file.h"
#include "header.h"
#include "http.h"
#include "memory.h"
#include "iov.h"
#include "epoll.h"
#include "worker.h"
#include "clock.h"

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
    if (p->hooks & MK_PLUGIN_STAGE_10) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_10, p);
    }

    if (p->hooks & MK_PLUGIN_STAGE_20) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_20, p);
    }

    if (p->hooks & MK_PLUGIN_STAGE_30) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_30, p);
    }

    if (p->hooks & MK_PLUGIN_STAGE_40) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_40, p);
    }

    if (p->hooks & MK_PLUGIN_STAGE_50) {
        mk_plugin_register_stagemap_add(&plg_stagemap->stage_50, p);
    }
}

struct plugin *mk_plugin_alloc(void *handler, char *path)
{
    struct plugin *p;
    struct plugin_info *info;

    p = mk_mem_malloc_z(sizeof(struct plugin));
    info = (struct plugin_info *) mk_plugin_load_symbol(handler, "_plugin_info");

    if (!info) {
        printf("\nPlugin Error: '%s'\nis not registering properly\n\n", path);
        exit(1);
    }

    p->shortname = (char *) (*info).shortname;
    p->name = (char *) (*info).name;
    p->version = (char *) (*info).version;
    p->hooks = (unsigned int) (*info).hooks;

    p->path = mk_string_dup(path);
    p->handler = handler;

    /* Mandatory functions */
    p->init = (int (*)()) mk_plugin_load_symbol(handler, "_mkp_init");
    p->exit = (int (*)()) mk_plugin_load_symbol(handler, "_mkp_exit");

    /* Core hooks */
    p->core.prctx = (int (*)()) mk_plugin_load_symbol(handler,
                                                      "_mkp_core_prctx");
    p->core.thctx = (int (*)()) mk_plugin_load_symbol(handler,
                                                      "_mkp_core_thctx");

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
    p->thread_key = (pthread_key_t *) mk_plugin_load_symbol(handler, 
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

    return p;
}

/* Load the plugins and set the library symbols to the
 * local struct plugin *p node
 */
struct plugin *mk_plugin_register(struct plugin *p)
{
    if (!p->name || !p->version || !p->hooks) {
#ifdef TRACE
        MK_TRACE("Plugin must define name, version and hooks. Check: %s", p->path);
#endif
        mk_plugin_free(p);
        return NULL;
    }

    if (!p->init || !p->exit) {
#ifdef TRACE
        MK_TRACE("Plugin must define hooks 'init' and 'exit'");
#endif        
        mk_plugin_free(p);
        return NULL;
    }

    /* NETWORK_IO Plugin */
    if (p->hooks & MK_PLUGIN_NETWORK_IO) {
        /* Validate mandatory calls */
        if (!p->net_io.accept || !p->net_io.read || !p->net_io.write ||
            !p->net_io.writev || !p->net_io.close || !p->net_io.connect ||
            !p->net_io.send_file || !p->net_io.create_socket || !p->net_io.bind ||
            !p->net_io.server ) {
#ifdef TRACE
                MK_TRACE("Networking IO plugin incomplete: %s", p->path);
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
                mk_plugin_free(p);
                return NULL;
            }

        /* Restrict to one NETWORK_IO plugin */
        if (!plg_netiomap) {
            plg_netiomap = &p->net_io;
        }
        else {
            fprintf(stderr,
                    "\nError: Loading more than one Network IO Plugin: %s",
                    p->path);
            exit(1);
        }
    }

    /* NETWORK_IP Plugin */
    if (p->hooks & MK_PLUGIN_NETWORK_IP) {
        /* Validate mandatory calls */
        if (!p->net_ip.addr || !p->net_ip.maxlen) {
#ifdef TRACE
            MK_TRACE("Networking IP plugin incomplete: %s", p->path);
            MK_TRACE("Mapped Functions\naddr   :%p\nmaxlen :%p",
                     p->net_ip.addr,
                     p->net_ip.maxlen);
#endif
            mk_plugin_free(p);
            return NULL;
        }

        /* Restrict to one NETWORK_IP plugin */
        if (!plg_netipmap) {
            plg_netipmap = &p->net_ip;
        }
        else {
            fprintf(stderr,
                    "\nError: Loading more than one Network IP Plugin: %s",
                    p->path);
            exit(1);
        }
    }

    /* Add Plugin to the end of the list */
    mk_list_add(&p->_head, config->plugins);

    /* Register plugins stages */
    mk_plugin_register_stagemap(p);
    return p;
}

void mk_plugin_unregister(struct plugin *p)
{
    mk_list_del(&p->_head);
    mk_plugin_free(p);
}

void mk_plugin_free(struct plugin *p)
{
    mk_mem_free(p->path);
    mk_mem_free(p);
    p = NULL;
}

void mk_plugin_init()
{
    int ret;
    char *path;
    char *plugin_confdir = 0;
    void *handle;
    unsigned long len;
    struct plugin *p;
    struct plugin_api *api;
    struct mk_config *cnf;
    struct mk_config_section *section;
    struct mk_config_entry *entry;

    api = mk_mem_malloc_z(sizeof(struct plugin_api));
    plg_stagemap = mk_mem_malloc_z(sizeof(struct plugin_stagemap));
    plg_netiomap = NULL;
    plg_netipmap = NULL;

    /* Setup and connections list */
    api->config = config;
    api->sched_list = &sched_list;

    /* API plugins funcions */

    /* HTTP callbacks */
    api->http_request_end = (void *) mk_plugin_http_request_end;

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
    api->str_itop = (void *) mk_string_itop;
    api->str_split_line = (void *) mk_string_split_line;

    /* File Callbacks */
    api->file_to_buffer = (void *) mk_file_to_buffer;
    api->file_get_info = (void *) mk_file_get_info;

    /* HTTP Callbacks */
    api->header_send = (void *) mk_header_send;
    api->header_set_http_status = (void *) mk_header_set_http_status;

    /* IOV callbacks */
    api->iov_create = (void *) mk_iov_create;
    api->iov_free = (void *) mk_iov_free;
    api->iov_add_entry = (void *) mk_iov_add_entry;
    api->iov_set_entry = (void *) mk_iov_set_entry;
    api->iov_send = (void *) mk_iov_send;
    api->iov_print = (void *) mk_iov_print;

    /* EPoll callbacks */
    api->epoll_create = (void *) mk_epoll_create;
    api->epoll_init = (void *) mk_epoll_init;
    api->epoll_add = (void *) mk_epoll_add;
    api->epoll_del = (void *) mk_epoll_del;
    api->epoll_change_mode = (void *) mk_epoll_change_mode;

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
    api->config_section_get = (void *) mk_config_section_get;
    api->config_section_getval = (void *) mk_config_section_getval;

    /* Scheduler and Event callbacks */
    api->sched_get_connection = (void *) mk_sched_get_connection;
    api->event_add = (void *) mk_plugin_event_add;
    api->event_del = (void *) mk_plugin_event_del;
    api->event_socket_change_mode = (void *) mk_plugin_event_socket_change_mode;
    
    /* Worker functions */
    api->worker_spawn = (void *) mk_worker_spawn;

    /* Some useful functions =) */
    api->sys_get_somaxconn = (void *) mk_utils_get_somaxconn;

    /* Time functions */
    api->time_unix = (void *) mk_plugin_time_now_unix;
    api->time_human = (void *) mk_plugin_time_now_human;

#ifdef TRACE
    api->trace = (void *) mk_utils_trace;
#endif

    /* Read configuration file */
    path = mk_mem_malloc_z(1024);
    snprintf(path, 1024, "%s/%s", config->serverconf, MK_PLUGIN_LOAD);
    cnf = mk_config_create(path);
    
    if (!cnf) {
        puts("Error: Plugins configuration file could not be readed");
        exit(1);
    }

    /* Read section 'PLUGINS' */
    section = mk_config_section_get(cnf, "PLUGINS");

    /* Read key entries */
    entry = section->entry;
    while (entry) {
        if (strcasecmp(entry->key, "Load") == 0) {
            handle = mk_plugin_load(entry->val);

            p = mk_plugin_alloc(handle, entry->val);
            if (!p) {
                fprintf(stderr, "Plugin error: %s\n", entry->val);
                dlclose(handle);
            }

            /* Build plugin configuration path */
            mk_string_build(&plugin_confdir,
                            &len,
                            "%s/plugins/%s/",
                            config->serverconf, p->shortname);

#ifdef TRACE
            MK_TRACE("Load Plugin '%s@%s'", p->shortname, p->path);
#endif
            
            /* Init plugin */
            ret = p->init(&api, plugin_confdir);
            if (ret < 0) {
                /* Free plugin, do not register */
#ifdef TRACE
                MK_TRACE("Unregister plugin '%s'", p->shortname);
#endif
                mk_plugin_free(p);
                entry = entry->next;
                continue;
            }

            /* If everything worked, register plugin */
            mk_plugin_register(p);
        }
        entry = entry->next;
    }

    if (!plg_netiomap) {
        fprintf(stderr, "\nError: no Network plugin loaded >:|\n\n");
        exit(1);
    }

    api->plugins = config->plugins;

    /* Look for plugins thread key data */
    mk_plugin_preworker_calls();
    mk_mem_free(path);
}

void mk_plugin_exit_all()
{
    struct plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct plugin, _head);
        node->exit();
    }
}

int mk_plugin_stage_run(unsigned int hook,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct client_session *cs, struct session_request *sr)
{
    int ret;
    struct plugin_stagem *stm;

    /* Connection just accept(ed) not assigned to worker thread */
    if (hook & MK_PLUGIN_STAGE_10) {
        stm = plg_stagemap->stage_10;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 10", stm->p->shortname);
#endif
            ret = stm->p->stage.s10(socket, conx);
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

    /* The HTTP Request stream has been just received */
    if (hook & MK_PLUGIN_STAGE_20) {
        stm = plg_stagemap->stage_20;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 20", stm->p->shortname);
#endif
            ret = stm->p->stage.s20(cs, sr);
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

    /* The plugin acts like an Object handler, it will take care of the 
     * request, it decides what to do with the request 
     */
    if (hook & MK_PLUGIN_STAGE_30) {
        /* The request just arrived and is required to check who can
         * handle it */
        if (!sr->handled_by){
            stm = plg_stagemap->stage_30;
            while (stm) {
                /* Call stage */
#ifdef TRACE
                MK_TRACE("[%s] STAGE 30", stm->p->shortname);
#endif
                ret = stm->p->stage.s30(stm->p, cs, sr);

                switch (ret) {
                case MK_PLUGIN_RET_NOT_ME:
                    break;
                case MK_PLUGIN_RET_CONTINUE:
                    return MK_PLUGIN_RET_CONTINUE;
                case MK_PLUGIN_RET_END:
                    return MK_PLUGIN_RET_END;
                }
                
                stm = stm->next;
            }
        }
    }

    /* The request has ended, the content has been served */
    if (hook & MK_PLUGIN_STAGE_40) {
        stm = plg_stagemap->stage_40;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 40", stm->p->shortname);
#endif
            ret = stm->p->stage.s40(cs, sr);
            stm = stm->next;
        }
    }

    /* The request has ended, the content has been served */
    if (hook & MK_PLUGIN_STAGE_50) {
        stm = plg_stagemap->stage_50;
        while (stm) {
#ifdef TRACE
            MK_TRACE("[%s] STAGE 50", stm->p->shortname);
#endif
            ret = stm->p->stage.s50(socket);
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

void mk_plugin_request_handler_add(struct session_request *sr, struct plugin *p)
{
    if (!sr->handled_by) {
        sr->handled_by = p;
        return;
    }
}

void mk_plugin_request_handler_del(struct session_request *sr, struct plugin *p)
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
void mk_plugin_core_process()
{
    struct plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct plugin, _head);
        
        /* Init plugin */
        if (node->core.prctx) {
            node->core.prctx(config);
        }
    }
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void mk_plugin_core_thread()
{

    struct plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct plugin, _head);

        /* Init plugin thread context */
        if (node->core.thctx) {
            node->core.thctx();
        }
    }
}

/* This function is called by Monkey *outside* of the
 * thread context for plugins, so here's the right
 * place to set pthread keys or similar
 */
void mk_plugin_preworker_calls()
{
    int ret;
    struct plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct plugin, _head);

        /* Init pthread keys */
        if (node->thread_key) {
#ifdef TRACE
            MK_TRACE("[%s] Set thread key", node->shortname);
#endif
            ret = pthread_key_create(node->thread_key, NULL);
            if (ret != 0) {
                printf("\nPlugin Error: could not create key for %s",
                       node->shortname);
                fflush(stdout);
                exit(1);
            }
        }
    }
}

int mk_plugin_event_del(int socket)
{
    struct plugin_event *list, *aux, *prev;

#ifdef TRACE
    MK_TRACE("[FD %i] Plugin delete event", socket);
#endif

    if (socket <= 0) {
        return -1;
    }

    list = mk_plugin_event_get_list();
    
    aux = list;
    while (aux) {
        if (aux->socket == socket) {
            if (aux == list) {
                list = aux->next;
            }
            else { 
                prev = list;
                while (prev->next != aux) {
                    prev = prev->next;
                }
            
                prev->next = aux->next;
            }
            mk_mem_free(aux);
            mk_plugin_event_set_list(list);
            return 0;
        }
        aux = aux->next;
    }

#ifdef TRACE
    MK_TRACE("[FD %i] not found :/");
    exit(1);
#endif

    return -1;
}

int mk_plugin_event_add(int socket, int mode,
                        struct plugin *handler,
                        struct client_session *cs,
                        struct session_request *sr)
{
    struct sched_list_node *sched;
    struct plugin_event *list;
    struct plugin_event *aux;
    struct plugin_event *event;

    sched = mk_sched_get_thread_conf();

    if (!sched || !handler || !cs || !sr) {
        return -1;
    }

    /* Event node (this list exist at thread level */
    event = mk_mem_malloc(sizeof(struct plugin_event));
    event->socket = socket;
    event->handler = handler;
    event->cs = cs;
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
        mk_plugin_event_set_list(list);
    }

    /* The thread event info has been registered, now we need
       to register the socket involved to the thread epoll array */
    mk_epoll_add(sched->epoll_fd, event->socket,
                 mode, MK_EPOLL_BEHAVIOR_DEFAULT);
    return 0;
}

int mk_plugin_http_request_end(int socket)
{
    int ret;

    ret = mk_http_request_end(socket);

#ifdef TRACE
    MK_TRACE("PLUGIN HTTP REQUEST END [FD=%i] = ret %i", socket, ret);
#endif

    if (ret < 0) {
        return mk_conn_close(socket);
    }

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
    return pthread_setspecific(mk_plugin_event_k, event);
}

struct plugin_event *mk_plugin_event_get_list()
{
    return pthread_getspecific(mk_plugin_event_k);

}

/* Plugin epoll event handlers
 * ---------------------------
 * this functions are called by connection.c functions as mk_conn_read(),
 * mk_conn_write(),mk_conn_error(), mk_conn_close() and mk_conn_timeout().
 *
 * Return Values:
 * -------------
 *    MK_PLUGIN_RET_EVENT_NOT_ME: There's no plugin hook associated
 */

int mk_plugin_event_read(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("[FD %i] Plugin event read", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
#ifdef TRACE
        MK_TRACE(" not handled by plugin");
#endif
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_read) {
#ifdef TRACE
        MK_TRACE(" handled by plugin");
#endif
        return event->handler->event_read(socket);
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_write(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("[FD %i] Plugin event write", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_write) {
        return event->handler->event_write(socket);
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_error(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("[FD %i] Plugin event error", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_error) {
        return event->handler->event_error(socket);
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_close(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("[FD %i] Plugin event close", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_close) {
        return event->handler->event_close(socket);
    }

    return 0;
}

int mk_plugin_event_timeout(int socket)
{
    struct plugin_event *event;

#ifdef TRACE
    MK_TRACE("[FD %i] Plugin event timeout", socket);
#endif

    event = mk_plugin_event_get(socket);
    if (!event) {
        return MK_PLUGIN_RET_EVENT_NOT_ME;
    }

    if (event->handler->event_timeout) {
        return event->handler->event_timeout(socket);
    }

    return 0;
}

int mk_plugin_time_now_unix()
{
    return log_current_utime;
}

mk_pointer *mk_plugin_time_now_human()
{
    return &log_current_time;
}
