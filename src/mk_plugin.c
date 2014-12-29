/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dlfcn.h>
#include <err.h>

#include <monkey/mk_connection.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_file.h>
#include <monkey/mk_http.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_stats.h>
#include <monkey/mk_static_plugins.h>

enum {
    bufsize = 256
};

static struct plugin_stagemap *plg_stagemap;
struct plugin_network_io *plg_netiomap;
struct plugin_api *api;

__thread struct mk_list *worker_plugin_event_list;

static void mk_plugin_event_set_list(struct mk_list *list)
{
    worker_plugin_event_list = list;
}

static struct mk_list *mk_plugin_event_get_list()
{
    return worker_plugin_event_list;
}

void *mk_plugin_load_dynamic(const char *path)
{
    void *handle;

    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        mk_warn("dlopen() %s", dlerror());
    }

    return handle;
}

void *mk_plugin_load_symbol(void *handler, const char *symbol)
{
    void *s;

    dlerror();
    s = dlsym(handler, symbol);
    if (dlerror() != NULL) {
        return NULL;
    }

    return s;
}

/*
 * Load a plugin into Monkey core, 'type' defines if it's a MK_PLUGIN_STATIC or
 * a MK_PLUGIN_DYNAMIC. 'shortname' is mandatory and 'path' is only used when
 * MK_PLUGIN_DYNAMIC is set and represents the absolute path of the shared
 * library.
 */
struct mk_plugin *mk_plugin_load(int type, const char *shortname,
                                 const char *path)
{
    char symbol[64];
    void *handler;
    struct mk_plugin *plugin;

    /* Set main struct name to reference */
    snprintf(symbol, sizeof(symbol) - 1, "mk_plugin_%s", shortname);
    if (type == MK_PLUGIN_DYNAMIC) {
        handler = mk_plugin_load_dynamic(path);
        if (!handler) {
            return NULL;
        }

        plugin  = mk_plugin_load_symbol(handler, symbol);
        if (!plugin) {
            mk_warn("Plugin '%s' is not registering properly", path);
            return NULL;
        }
    }
    else if (type == MK_PLUGIN_STATIC) {
        /* fixme! */
        //plugin = *plugin_info;
    }

    /* Validate all callbacks are set */
    if (!plugin->shortname || !plugin->name || !plugin->version ||
        !plugin->hooks || !plugin->init_plugin || !plugin->exit_plugin) {
        mk_warn("Plugin '%s' is not registering all fields properly",
                shortname);
        return NULL;
    }

    if (plugin->hooks & MK_PLUGIN_NETWORK_LAYER) {
        snprintf(symbol, sizeof(symbol) - 1, "mk_plugin_network_%s", shortname);
        plugin->network = mk_plugin_load_symbol(handler, symbol);

        /* Set Transport Layer */
        if (config->transport_layer &&
            strcmp(config->transport_layer, plugin->shortname) == 0) {
            config->transport_layer_plugin = plugin;
            config->network = plugin->network;

            /* Ask the transport layer if it's using any buffer size */
            config->transport_buffer_size = plugin->network->buffer_size();
            if (config->transport_buffer_size <= 0) {
                config->transport_buffer_size = MK_REQUEST_CHUNK;
            }
        }
    }

    /* Add Plugin to the end of the list */
    mk_list_add(&plugin->_head, config->plugins);

    return plugin;
}

void mk_plugin_unregister(struct mk_plugin *p)
{
    mk_list_del(&p->_head);
    mk_plugin_free(p);
}

void mk_plugin_free(struct mk_plugin *p)
{
    mk_mem_free(p->path);
    mk_mem_free(p);
    p = NULL;
}

void mk_plugin_init()
{
    struct mk_list *static_plugins;
    struct mk_list *head, *tmp;
    struct mk_plugin *plugin;

    /* Load static plugins, iterate and re-set on global config */
    static_plugins = mk_static_plugins();
    mk_list_foreach_safe(head, tmp, static_plugins) {
        plugin = mk_list_entry(head, struct mk_plugin, _head);
        printf("Test Static: %s\n", plugin->shortname);
        mk_list_add(&plugin->_head, config->plugins);
    }


    api = mk_mem_malloc_z(sizeof(struct plugin_api));
    __builtin_prefetch(api);

    plg_stagemap = mk_mem_malloc_z(sizeof(struct plugin_stagemap));
    plg_netiomap = NULL;

    /* Setup and connections list */
    api->config = config;
    api->sched_list = sched_list;

    /* API plugins funcions */

    /* Error helper */
    api->_error = mk_print;

    /* HTTP callbacks */
    api->http_request_end = mk_plugin_http_request_end;
    api->http_request_error = mk_http_error;

    /* Memory callbacks */
    api->pointer_set = mk_ptr_set;
    api->pointer_print = mk_ptr_print;
    api->pointer_to_buf = mk_ptr_to_buf;
    api->plugin_load_symbol = mk_plugin_load_symbol;
    api->mem_alloc = mk_mem_malloc;
    api->mem_alloc_z = mk_mem_malloc_z;
    api->mem_realloc = mk_mem_realloc;
    api->mem_free = mk_mem_free;

    /* String Callbacks */
    api->str_build = mk_string_build;
    api->str_dup = mk_string_dup;
    api->str_search = mk_string_search;
    api->str_search_n = mk_string_search_n;
    api->str_char_search = mk_string_char_search;
    api->str_copy_substr = mk_string_copy_substr;
    api->str_itop = mk_string_itop;
    api->str_split_line = mk_string_split_line;
    api->str_split_free = mk_string_split_free;

    /* File Callbacks */
    api->file_to_buffer = mk_file_to_buffer;
    api->file_get_info = mk_file_get_info;

    /* HTTP Callbacks */
    api->header_send = mk_header_send;
    api->header_add = mk_plugin_header_add;
    api->header_get = mk_http_header_get;
    api->header_set_http_status = mk_header_set_http_status;

    /* IOV callbacks */
    api->iov_create  = mk_iov_create;
    api->iov_realloc = mk_iov_realloc;
    api->iov_free = mk_iov_free;
    api->iov_free_marked = mk_iov_free_marked;
    api->iov_add_entry =  mk_iov_add_entry;
    api->iov_set_entry =  mk_iov_set_entry;
    api->iov_send =  mk_iov_send;
    api->iov_print =  mk_iov_print;

    /* events mechanism */
    api->ev_loop_create = mk_event_loop_create;
    api->ev_get_fdt = mk_event_get_fdt;
    api->ev_add = mk_event_add;
    api->ev_del = mk_event_del;
    api->ev_timeout_create = mk_event_timeout_create;
    api->ev_channel_create = mk_event_channel_create;
    api->ev_wait = mk_event_wait;
    api->ev_translate = mk_event_translate;
    api->ev_backend = mk_event_backend;

    /* Red-Black tree */
    api->rb_insert_color = rb_insert_color;
    api->rb_erase = rb_erase;
    api->rb_link_node = rb_link_node;

    /* Mimetype */
    api->mimetype_lookup = mk_mimetype_lookup;

    /* Socket callbacks */
    api->socket_cork_flag = mk_socket_set_cork_flag;
    api->socket_connect = mk_socket_connect;
    api->socket_reset = mk_socket_reset;
    api->socket_set_tcp_fastopen = mk_socket_set_tcp_fastopen;
    api->socket_set_tcp_reuseport = mk_socket_set_tcp_reuseport;
    api->socket_set_tcp_nodelay = mk_socket_set_tcp_nodelay;
    api->socket_set_nonblocking = mk_socket_set_nonblocking;
    api->socket_create = mk_socket_create;
    api->socket_close = mk_socket_close;
    api->socket_sendv = mk_socket_sendv;
    api->socket_send = mk_socket_send;
    api->socket_read = mk_socket_read;
    api->socket_send_file = mk_socket_send_file;
    api->socket_ip_str = mk_socket_ip_str;

    /* Config Callbacks */
    api->config_create = mk_config_create;
    api->config_free = mk_config_free;
    api->config_section_get = mk_config_section_get;
    api->config_section_getval = mk_config_section_getval;

    /* Scheduler and Event callbacks */
    api->sched_get_connection = mk_sched_get_connection;
    api->sched_remove_client  = mk_plugin_sched_remove_client;
    api->sched_worker_info    = mk_plugin_sched_get_thread_conf;

    api->event_add = mk_plugin_event_add;
    api->event_del = mk_plugin_event_del;
    api->event_get = mk_plugin_event_get;
    api->event_socket_change_mode = mk_plugin_event_socket_change_mode;

    /* Worker functions */
    api->worker_spawn = mk_utils_worker_spawn;
    api->worker_rename = mk_utils_worker_rename;

    /* Time functions */
    api->time_unix   = mk_plugin_time_now_unix;
    api->time_to_gmt = mk_utils_utime2gmt;
    api->time_human  = mk_plugin_time_now_human;

#ifdef TRACE
    api->trace = mk_utils_trace;
    api->errno_print = mk_utils_print_errno;
#endif

#ifdef JEMALLOC_STATS
    api->je_mallctl = je_mallctl;
#endif

    api->stacktrace = (void *) mk_utils_stacktrace;
    api->kernel_version = mk_kernel_version;
    api->kernel_features_print = mk_kernel_features_print;
    api->plugins = config->plugins;
}

#ifndef SHAREDLIB

void mk_plugin_read_config()
{
    int ret;
    char *path;
    char *plugin_confdir = 0;
    char *tmp;
    char shortname[64];
    unsigned long len;
    struct mk_plugin *p;
    struct mk_config *cnf;
    struct mk_config_section *section;
    struct mk_config_entry *entry;
    struct mk_list *head;
    struct file_info f_info;

    /* Read configuration file */
    path = mk_mem_malloc_z(1024);
    snprintf(path, 1024, "%s/%s", config->serverconf,
             config->plugin_load_conf_file);

    ret = mk_file_get_info(path, &f_info);
    if (ret == -1 || f_info.is_file == MK_FALSE) {
        snprintf(path, 1024, "%s", config->plugin_load_conf_file);
    }

    cnf = mk_config_create(path);
    if (!cnf) {
        mk_err("Configuration error, aborting.");
        mk_mem_free(path);
        exit(EXIT_FAILURE);
    }

    snprintf(path, 1024, "%s/%s", config->serverconf, config->plugins_conf_dir);
    ret = mk_file_get_info(path, &f_info);
    if (ret == -1 || f_info.is_directory == MK_FALSE)
        snprintf(path, 1024, "%s", config->plugins_conf_dir);

    /* Read section 'PLUGINS' */
    section = mk_config_section_get(cnf, "PLUGINS");
    if (!section) {
        exit(EXIT_FAILURE);
    }

    /* Read key entries */
    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);
        if (strcasecmp(entry->key, "Load") == 0) {

            /* Get plugin 'shortname' */
            tmp = memrchr(entry->val, '-', strlen(entry->val));
            ++tmp;
            memset(shortname, '\0', sizeof(shortname) - 1);
            strncpy(shortname, tmp, strlen(tmp) - 3);

            /* Load the dynamic plugin */
            p = mk_plugin_load(MK_PLUGIN_DYNAMIC,
                               shortname,
                               entry->val);
            if (!p) {
                mk_warn("Invalid plugin '%s'", entry->val);
                continue;
            }

            /* Build plugin configuration path */
            mk_string_build(&plugin_confdir,
                    &len,
                    "%s/%s/",
                    path, p->shortname);

            MK_TRACE("Load Plugin '%s@%s'", p->shortname, p->path);

            /* Init plugin */
            ret = p->init_plugin(&api, plugin_confdir);
            if (ret < 0) {
                /* Free plugin, do not register */
                MK_TRACE("Unregister plugin '%s'", p->shortname);

                mk_plugin_free(p);
                mk_mem_free(plugin_confdir);
                plugin_confdir  = NULL;
                continue;
            }

            mk_mem_free(plugin_confdir);
            plugin_confdir = NULL;
        }
    }

    if (!config->transport_layer) {
        mk_err("TransportLayer not defined in configuration");
        exit(EXIT_FAILURE);
    }

    /* Look for plugins thread key data */
    mk_plugin_preworker_calls();
    mk_mem_free(path);
    mk_config_free(cnf);
}

#endif //!SHAREDLIB

/* Invoke all plugins 'exit' hook and free resources by the plugin interface */
void mk_plugin_exit_all()
{
    struct mk_plugin *node;
    struct mk_list *head, *tmp;

    /* Plugins */
    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        node->exit_plugin();
    }

    /* Plugin interface it self */
    mk_list_foreach_safe(head, tmp, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        mk_list_del(&node->_head);
        mk_mem_free(node->path);
        dlclose(node->handler);
        mk_mem_free(node);
    }
    mk_mem_free(api);
    mk_mem_free(plg_stagemap);
}

/*
 * When a worker is exiting, it invokes this function to release any plugin
 * associated data.
 */
void mk_plugin_exit_worker()
{
    struct mk_list *list;
    struct mk_list *head;
    struct mk_list *tmp;
    struct plugin_event *pe;

    /* For each plugin on this context, exit worker zone */


    /* Remove plugins events */
    list = mk_plugin_event_get_list();
    if (list) {
        mk_list_foreach_safe(head, tmp, list) {
            pe = mk_list_entry(head, struct plugin_event, _head);
            mk_list_del(&pe->_head);
            mk_mem_free(pe);
        }
        mk_mem_free(list);
    }
}

int mk_plugin_stage_run(unsigned int hook,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct mk_http_session *cs, struct mk_http_request *sr)
{
    int ret;
    struct plugin_stagem *stm;


#ifdef SHAREDLIB
    struct sched_list_node *thconf = mk_sched_get_thread_conf();
    mklib_ctx ctx = thconf->ctx;
    char buf[bufsize], *ptr = buf;
    unsigned long len;

    if (hook & MK_PLUGIN_STAGE_10 && ctx->ipf) {
        mk_socket_ip_str(socket, &ptr, bufsize, &len);
        ret = ctx->ipf(buf);
        if (ret == MKLIB_FALSE) {
            return MK_PLUGIN_RET_CLOSE_CONX;
        }
    }

    if (hook & MK_PLUGIN_STAGE_20 && ctx->urlf) {
        len = sr->uri.len;
        if (len >= bufsize) len = bufsize - 1;
        strncpy(buf, sr->uri.data, len);
        buf[len] = '\0';

        ret = ctx->urlf(buf);
        if (ret == MKLIB_FALSE) {
            return MK_PLUGIN_RET_CLOSE_CONX;
        }
    }

#endif

    /* Connection just accept(ed) not assigned to worker thread */
    if (hook & MK_PLUGIN_STAGE_10) {
        /*
        stm = plg_stagemap->stage_10;
        while (stm) {
            MK_TRACE("[%s] STAGE 10", stm->p->shortname);
            ret = stm->p->stage.s10(socket, conx);
            switch (ret) {
            case MK_PLUGIN_RET_CLOSE_CONX:
                MK_TRACE("return MK_PLUGIN_RET_CLOSE_CONX");
                return MK_PLUGIN_RET_CLOSE_CONX;
            }

            stm = stm->next;
        }
        */
    }

    /* The HTTP Request stream has been just received */
    if (hook & MK_PLUGIN_STAGE_20) {
        /*
        stm = plg_stagemap->stage_20;
        while (stm) {
            MK_TRACE("[%s] STAGE 20", stm->p->shortname);

            ret = stm->p->stage.s20(cs, sr);
            switch (ret) {
            case MK_PLUGIN_RET_CLOSE_CONX:
                MK_TRACE("return MK_PLUGIN_RET_CLOSE_CONX");

                return MK_PLUGIN_RET_CLOSE_CONX;
            }

            stm = stm->next;
        }
        */
    }

    /*
     * The plugin acts like an Object handler, it will take care of the
     * request, it decides what to do with the request
     */
    if (hook & MK_PLUGIN_STAGE_30) {
        /* The request just arrived and is required to check who can
         * handle it */

        /*
        stm = plg_stagemap->stage_30;
        while (stm) {
            MK_TRACE("[%s] STAGE 30", stm->p->shortname);
            ret = stm->p->stage.s30(stm->p, cs, sr);

            switch (ret) {
                case MK_PLUGIN_RET_NOT_ME:
                    break;
                case MK_PLUGIN_RET_END:
                    mk_bug(sr->headers.sent == MK_FALSE);
                    return ret;
                case MK_PLUGIN_RET_CLOSE_CONX:
                case MK_PLUGIN_RET_CONTINUE:
                    return ret;
                default:
                    mk_err("Plugin '%s' returns invalid value %i",
                           stm->p->shortname, ret);
                    exit(EXIT_FAILURE);
            }
            stm = stm->next;
        }
        */
    }

    /* The request has ended, the content has been served */
    if (hook & MK_PLUGIN_STAGE_40) {
        /*
        stm = plg_stagemap->stage_40;
        while (stm) {
            MK_TRACE("[%s] STAGE 40", stm->p->shortname);

            stm->p->stage.s40(cs, sr);
            stm = stm->next;
        }
        */
    }

    /* The request has ended, the content has been served */
    if (hook & MK_PLUGIN_STAGE_50) {
        /*
        stm = plg_stagemap->stage_50;
        while (stm) {
            MK_TRACE("[%s] STAGE 50", stm->p->shortname);

            ret = stm->p->stage.s50(socket);
            switch (ret) {
            case MK_PLUGIN_RET_NOT_ME:
                break;
            case MK_PLUGIN_RET_CONTINUE:
                return MK_PLUGIN_RET_CONTINUE;
            }
            stm = stm->next;
        }
        */
    }

#ifdef SHAREDLIB

    if (hook & MK_PLUGIN_STAGE_30 && ctx->dataf) {
        unsigned int status = 200;
        unsigned long clen, get_len = 0, post_len = 0;
        const char *content;
        char *get = NULL, *post = NULL;
        char header[bufsize] = "";

        if (sr->query_string.data) {
            get = mk_mem_malloc_z(sr->query_string.len + 1);
            memcpy(get, sr->query_string.data, sr->query_string.len);
            get_len = sr->query_string.len;
        }
        if (sr->data.data) {
            post = mk_mem_malloc_z(sr->data.len + 1);
            memcpy(post, sr->data.data, sr->data.len);
            post_len = sr->data.len;
        }

        len = sr->uri.len;
        if (len >= bufsize) len = bufsize - 1;
        strncpy(buf, sr->uri.data, len);
        buf[len] = '\0';

        ret = ctx->dataf(sr, sr->host_conf->file, buf,
                         get, get_len, post, post_len,
                         &status, &content, &clen, header);
        mk_mem_free(get);
        mk_mem_free(post);

        if (ret == MKLIB_FALSE) {
            return -1;
        }

        /* Status */
        api->header_set_http_status(sr, status);

        /* Headers */
        sr->headers.content_length = clen;
        len = strlen(header);
        if (len) api->header_add(sr, header, len);
        api->header_send(socket, cs, sr);

        /* Data */
        while (clen > 0) {
            int remaining = api->socket_send(socket, content, clen);
            if (remaining < 0) {
                /*
                 * FIXME: This is a temporal fix to send out the data,
                 * this is working in blocking mode. This will be fixed
                 * shortly once the 'pending buffers' interface is
                 * implemented.
                 */
                if (errno == EAGAIN) {
                    continue;
                }
                return -1;
            }
            clen -= remaining;
            content += remaining;
        }
        mk_socket_set_cork_flag(socket, TCP_CORK_OFF);

        if (ret == MKLIB_TRUE) {
            return MK_PLUGIN_RET_END;
        }
    }

    if (hook & MK_PLUGIN_STAGE_40 && ctx->closef) {
        ctx->closef(sr);
    }

#endif

    return -1;
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void mk_plugin_core_process()
{
    struct mk_plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);

        /* Init plugin */
        if (node->master_init) {
            node->master_init(config);
        }
    }
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void mk_plugin_core_thread()
{

    struct mk_plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);

        /* Init plugin thread context */
        if (node->worker_init) {
            node->worker_init();
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
    struct mk_plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);

        /* Init pthread keys */
        if (node->thread_key) {
            MK_TRACE("[%s] Set thread key", node->shortname);

            ret = pthread_key_create(node->thread_key, NULL);
            if (ret != 0) {
                mk_err("Plugin Error: could not create key for %s",
                       node->shortname);
            }
        }
    }
}

int mk_plugin_event_del(int socket)
{
    struct mk_list *head, *list, *temp;
    struct plugin_event *node;

    MK_TRACE("[FD %i] Plugin delete event", socket);

    if (socket <= 0) {
        return -1;
    }

    list = mk_plugin_event_get_list();
    mk_list_foreach_safe(head, temp, list) {
        node = mk_list_entry(head, struct plugin_event, _head);
        if (node->socket == socket) {
            mk_list_del(head);
            mk_mem_free(node);

            struct sched_list_node *sched = mk_sched_get_thread_conf();
            mk_event_del(sched->loop, socket);
            return 0;
        }
    }

    MK_TRACE("[FD %i] not found, could not delete event node :/");
    return -1;
}

int mk_plugin_event_add(int socket, int mode,
                        struct mk_plugin *handler,
                        unsigned int behavior)
{
    struct sched_list_node *sched;
    struct plugin_event *event;
    struct mk_list *list;
    (void) behavior;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return -1;
    }

    if (sched && handler) {
        /* Event node (this list exist at thread level */
        event = mk_mem_malloc(sizeof(struct plugin_event));
        event->socket = socket;
        event->handler = handler;

        /* Get thread event list */
        list = mk_plugin_event_get_list();
        mk_list_add(&event->_head, list);
    }

    /*
     * The thread event info has been registered, now we need
     * to register the socket involved to the thread epoll array
     */
    return mk_event_add(sched->loop, socket, mode, NULL);
}

int mk_plugin_http_request_end(int socket)
{
    int ret;
    int con;
    struct mk_http_session *cs;
    struct mk_http_request *sr;

    MK_TRACE("[FD %i] PLUGIN HTTP REQUEST END", socket);

    cs = mk_http_session_get(socket);
    if (!cs) {
        return -1;
    }

    if (!mk_list_is_empty(&cs->request_list)) {
        mk_err("[FD %i] Tried to end non-existing request.", socket);
        return -1;
    }

    sr = mk_list_entry_last(&cs->request_list, struct mk_http_request, _head);
    mk_plugin_stage_run(MK_PLUGIN_STAGE_40, socket, NULL, cs, sr);

    ret = mk_http_request_end(socket);
    MK_TRACE(" ret = %i", ret);

    if (ret < 0) {
        con = mk_conn_close(socket, MK_EP_SOCKET_CLOSED);
        if (con != 0) {
            return con;
        }
        else {
            return -1;
        }
    }

    return 0;
}

int mk_plugin_event_socket_change_mode(int socket, int mode, unsigned int behavior)
{
    struct sched_list_node *sched;
    (void) behavior;

    sched = mk_sched_get_thread_conf();

    if (!sched) {
        return -1;
    }

    return mk_event_add(sched->loop, socket, mode, NULL);
}

struct plugin_event *mk_plugin_event_get(int socket)
{
    struct mk_list *head, *list;
    struct plugin_event *node;

    list = mk_plugin_event_get_list();

    /*
     * In some cases this function is invoked from scheduler.c when a connection is
     * closed, on that moment there's no thread context so the returned list is NULL.
     */
    if (!list) {
        return NULL;
    }

    mk_list_foreach(head, list) {
        node = mk_list_entry(head, struct plugin_event, _head);
        if (node->socket == socket) {
            return node;
        }
    }

    return NULL;
}

void mk_plugin_event_init_list()
{
    struct mk_list *list;

    list = mk_mem_malloc(sizeof(struct mk_list));
    mk_list_init(list);

    mk_plugin_event_set_list(list);
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

void mk_plugin_event_bad_return(const char *hook, int ret)
{
    mk_err("[%s] Not allowed return value %i", hook, ret);
}

static inline int mk_plugin_event_check_return(const char *hook, int ret)
{
#ifdef TRACE
    MK_TRACE("Hook '%s' returned %i", hook, ret);
    switch(ret) {
    case MK_PLUGIN_RET_EVENT_NEXT:
        MK_TRACE("ret = MK_PLUGIN_RET_EVENT_NEXT");
        break;
    case MK_PLUGIN_RET_EVENT_OWNED:
        MK_TRACE("ret = MK_PLUGIN_RET_EVENT_OWNED");
        break;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        MK_TRACE("ret = MK_PLUGIN_RET_EVENT_CLOSE");
        break;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        MK_TRACE("ret = MK_PLUGIN_RET_EVENT_CONTINUE");
        break;
    default:
        MK_TRACE("ret = UNKNOWN, bad monkey!, follow the spec! >:D");
    }
#endif

    switch(ret) {
    case MK_PLUGIN_RET_EVENT_NEXT:
    case MK_PLUGIN_RET_EVENT_OWNED:
    case MK_PLUGIN_RET_EVENT_CLOSE:
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        return 0;
    default:
        mk_plugin_event_bad_return(hook, ret);
    }

    /* don't cry gcc :_( */
    return -1;
}

int mk_plugin_event_read(int socket)
{
    int ret;
    struct mk_plugin *node;
    struct mk_list *head;
    struct plugin_event *event;
    struct mk_event_fd_state *state;

    MK_TRACE("[FD %i] Plugin Read Event", socket);

    /*
     * Before to process this socket, we need to make sure
     * that is still an active connection and was not closed
     * in the middle by a timeout.
     */
    state = mk_event_get_state(socket);
    if (state->mask & MK_EVENT_EMPTY) {
        MK_TRACE("[FD %i] Connection already closed", socket);
        return -1;
    }

    /* Socket registered by plugin */
    event = mk_plugin_event_get(socket);
    if (event) {
        /* FIXME: events handler disabled

        if (event->handler->event_read) {
            MK_TRACE("[%s] plugin handler",  event->handler->name);

            ret = event->handler->event_read(socket);
            mk_plugin_event_check_return("read|handled_by", ret);
            return ret;
        }
        */
    }

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        /* FIXME: events handler disabled

        if (node->event_read) {
            ret = node->event_read(socket);

             validate return value
            mk_plugin_event_check_return("read", ret);
            if (ret == MK_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
        */
    }

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int mk_plugin_event_write(int socket)
{
    int ret;
    struct mk_plugin *node;
    struct mk_list *head;
    struct plugin_event *event;
    struct mk_event_fd_state *state;

    MK_TRACE("[FD %i] Plugin event write", socket);

    /*
     * Before to process this socket, we need to make sure
     * that is still an active connection and was not closed
     * in the middle by a timeout.
     */
    state = mk_event_get_state(socket);
    if (state->mask & MK_EVENT_EMPTY) {
        MK_TRACE("[FD %i] Connection already closed", socket);
        return -1;
    }

    event = mk_plugin_event_get(socket);
    if (event) {
        /* FIXME: events handler disabled

        if (event->handler->event_write) {
            MK_TRACE(" event write handled by plugin");

            ret = event->handler->event_write(socket);
            mk_plugin_event_check_return("write|handled_by", ret);
            return ret;
        }
        */
    }

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        /* FIXME: events handler disabled

        if (node->event_write) {

            ret = node->event_write(socket);

             validate return value
            mk_plugin_event_check_return("write", ret);
            if (ret == MK_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
        */
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_error(int socket)
{
    int ret;
    struct mk_plugin *node;
    struct mk_list *head;
    struct plugin_event *event;

    MK_TRACE("[FD %i] Plugin event error", socket);

    event = mk_plugin_event_get(socket);
    if (event) {
        /* FIXME: events handler disabled

        if (event->handler->event_error) {
            MK_TRACE(" event error handled by plugin");

            ret = event->handler->event_error(socket);
            mk_plugin_event_check_return("error|handled_by", ret);
            return ret;
        }
        */
    }

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        /* FIXME: events handler disabled

        if (node->event_error) {
            ret = node->event_error(socket);

             validate return value
            mk_plugin_event_check_return("error", ret);
            if (ret == MK_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
        */
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_close(int socket)
{
    int ret;
    struct mk_plugin *node;
    struct mk_list *head;
    struct plugin_event *event;

    MK_TRACE("[FD %i] Plugin event close", socket);

    event = mk_plugin_event_get(socket);
    if (event) {
        /* FIXME: events handler disabled

        if (event->handler->event_close) {
            MK_TRACE(" event close handled by plugin");

            ret = event->handler->event_close(socket);
            mk_plugin_event_check_return("close|handled_by", ret);
            return ret;
        }

        */
    }

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        /* FIXME: events handler disabled

        if (node->event_close) {
            ret = node->event_close(socket);

             validate return value
            mk_plugin_event_check_return("close", ret);
            if (ret == MK_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
        */
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_event_timeout(int socket)
{
    int ret;
    struct mk_plugin *node;
    struct mk_list *head;
    struct plugin_event *event;

    MK_TRACE("[FD %i] Plugin event timeout", socket);

    event = mk_plugin_event_get(socket);
    if (event) {
        /* FIXME: events handler disabled

        if (event->handler->event_timeout) {
            MK_TRACE(" event close handled by plugin");

            ret = event->handler->event_timeout(socket);
            mk_plugin_event_check_return("timeout|handled_by", ret);
            return ret;
        }

        */
    }

    mk_list_foreach(head, config->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);
        /* FIXME: events handler disabled

        if (node->event_timeout) {
            ret = node->event_timeout(socket);

             validate return value
            mk_plugin_event_check_return("timeout", ret);
            if (ret == MK_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
        */
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_plugin_time_now_unix()
{
    return log_current_utime;
}

mk_ptr_t *mk_plugin_time_now_human()
{
    return &log_current_time;
}

int mk_plugin_sched_remove_client(int socket)
{
    struct sched_list_node *node;

    MK_TRACE("[FD %i] remove client", socket);

    node = mk_sched_get_thread_conf();
    return mk_sched_remove_client(node, socket);
}

int mk_plugin_header_add(struct mk_http_request *sr, char *row, int len)
{
    mk_bug(!sr);

    if (!sr->headers._extra_rows) {
        /*
         * We allocate space for a fixed number of IOV entries:
         *
         *   MK_PLUGIN_HEADER_EXTRA_ROWS = X
         *
         *  we use (MK_PLUGIN_HEADER_EXTRA_ROWS * 2) thinking in an ending CRLF
         */
        sr->headers._extra_rows = mk_iov_create(MK_PLUGIN_HEADER_EXTRA_ROWS * 2, 0);
        mk_bug(!sr->headers._extra_rows);
    }

    mk_iov_add_entry(sr->headers._extra_rows, row, len,
                     mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
    return 0;
}

struct sched_list_node *mk_plugin_sched_get_thread_conf()
{
    return worker_sched_node;
}
