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

#include "mk_memory.h"
#include "mk_list.h"

#ifndef MK_CONFIG_H
#define MK_CONFIG_H

#include <unistd.h>
#include <sys/types.h>

#ifndef O_NOATIME
#define O_NOATIME       01000000
#endif

#define MK_DEFAULT_CONFIG_FILE              "monkey.conf"
#define MK_DEFAULT_MIMES_CONF_FILE          "monkey.mime"
#define MK_DEFAULT_PLUGIN_LOAD_CONF_FILE    "plugins.load"
#define MK_DEFAULT_SITES_CONF_DIR           "sites/"
#define MK_DEFAULT_PLUGINS_CONF_DIR         "plugins/"
#define MK_DEFAULT_LISTEN_ADDR              "0.0.0.0"
#define MK_WORKERS_DEFAULT                  1

#define VALUE_ON "on"
#define VALUE_OFF "off"

#define MK_CONFIG_VAL_STR 0
#define MK_CONFIG_VAL_NUM 1
#define MK_CONFIG_VAL_BOOL 2
#define MK_CONFIG_VAL_LIST 3

/* Indented configuration */
struct mk_config
{
    int created;
    char *file;

    /* list of sections */
    struct mk_list sections;
};

struct mk_config_section
{
    char *name;

    struct mk_list entries;
    struct mk_list _head;
};

struct mk_config_entry
{
    char *key;
    char *val;

    struct mk_list _head;
};

/* Base struct of server */
struct server_config
{
    int server_fd;                /* server socket file descriptor */
    int kernel_features;          /* Hold different server setup status */
    unsigned int worker_capacity; /* how many clients per thread... */
    unsigned int max_load;        /* max number of clients (worker_capacity * workers) */
    short int workers;            /* number of worker threads */
    short int manual_tcp_cork;    /* If enabled it will handle TCP_CORK */

    int8_t fdt;                   /* is FDT enabled ? */
    int8_t is_daemon;
    int8_t is_seteuid;
    int8_t scheduler_mode;        /* Scheduler balancing mode */

    char *serverconf;             /* path to configuration files */
    char *listen_addr;
    mk_ptr_t server_addr;
    mk_ptr_t server_software;

    char *user;
    char *user_dir;
    char *pid_file_path;        /* pid of server */
    char *path_config;
    char *server_conf_file;
    char *mimes_conf_file;
    char *plugin_load_conf_file;
    char *sites_conf_dir;
    char *plugins_conf_dir;
    char **request_headers_allowed;

    int serverport;             /* port */
    int timeout;                /* max time to wait for a new connection */
    int standard_port;          /* common port used in web servers (80) */
    int pid_status;
    int8_t hideversion;           /* hide version of server to clients ? */
    int8_t resume;                /* Resume (on/off) */
    int8_t symlink;               /* symbolic links */

    /* keep alive */
    int8_t keep_alive;            /* it's a persisten connection ? */
    int max_keep_alive_request; /* max persistent connections to allow */
    int keep_alive_timeout;     /* persistent connection timeout */

    /* counter of threads working */
    int thread_counter;
    /* real user */
    uid_t egid;
    gid_t euid;

    int max_request_size;

    struct mk_list *index_files;

    /* configured host quantity */
    int nhosts;
    struct mk_list hosts;

    mode_t open_flags;
    struct mk_list *plugins;

    /* Safe EPOLLOUT event */
    int safe_event_write;

    /* Transport type: HTTP or HTTPS, useful for redirections */
    char *transport;

    /* Define the plugin who provides the transport layer */
    char *transport_layer;
    struct plugin *transport_layer_plugin;

    /* Define the default mime type when is not possible to find the proper one */
    char *default_mimetype;

    /* source configuration */
    struct mk_config *config;
};

extern struct server_config *config;


/* Functions */
void mk_config_start_configure(void);
void mk_config_add_index(char *indexname);
void mk_config_set_init_values(void);

/* config helpers */
void mk_config_error(const char *path, int line, const char *msg);

struct mk_config *mk_config_create(const char *path);
struct mk_config_section *mk_config_section_get(struct mk_config *conf,
                                                const char *section_name);
struct mk_config_section *mk_config_section_add(struct mk_config *conf,
                                                char *section_name);
void *mk_config_section_getval(struct mk_config_section *section, char *key, int mode);

void mk_config_free(struct mk_config *cnf);
void mk_config_free_all();
void mk_config_free_entries(struct mk_config_section *section);


int mk_config_get_bool(char *value);
void mk_config_read_hosts(char *path);
void mk_config_sanity_check(void);

#endif
