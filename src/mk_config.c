/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

/* isblank is not in C89 */
#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>

#include <monkey/monkey.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_config.h>
#include <monkey/mk_string.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_info.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_server.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_mimetype.h>

struct mk_server_config *mk_config;
gid_t EGID;
gid_t EUID;


struct mk_server_config *mk_config_init()
{
    struct mk_server_config *config;

    config = mk_mem_malloc_z(sizeof(struct mk_server_config));
    mk_list_init(&config->stage10_handler);
    mk_list_init(&config->stage20_handler);
    mk_list_init(&config->stage30_handler);
    mk_list_init(&config->stage40_handler);
    mk_list_init(&config->stage50_handler);

    return config;
}

/* Raise a configuration schema error */
void mk_config_error(const char *path, int line, const char *msg)
{
    mk_err("File %s", path);
    mk_err("Error in line %i: %s", line, msg);
    exit(EXIT_FAILURE);
}

/* Raise a warning */
void mk_config_warning(const char *path, int line, const char *msg)
{
    mk_warn("Config file warning '%s':\n"
            "\t\t\t\tat line %i: %s",
            path, line, msg);
}

/* Returns a configuration section by [section name] */
struct mk_config_section *mk_config_section_get(struct mk_config *conf,
                                                const char *section_name)
{
    struct mk_config_section *section;
    struct mk_list *head;

    mk_list_foreach(head, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        if (strcasecmp(section->name, section_name) == 0) {
            return section;
        }
    }

    return NULL;
}

/* Register a new section into the configuration struct */
struct mk_config_section *mk_config_section_add(struct mk_config *conf,
                                                char *section_name)
{
    struct mk_config_section *new;

    /* Alloc section node */
    new = mk_mem_malloc(sizeof(struct mk_config_section));
    new->name = mk_string_dup(section_name);
    mk_list_init(&new->entries);
    mk_list_add(&new->_head, &conf->sections);

    return new;
}

/* Register a key/value entry in the last section available of the struct */
static void mk_config_entry_add(struct mk_config *conf,
                         const char *key, const char *val)
{
    struct mk_config_section *section;
    struct mk_config_entry *new;
    struct mk_list *head = &conf->sections;

    if (mk_list_is_empty(&conf->sections) == 0) {
        mk_err("Error: there are not sections available on %s!", conf->file);
        return;
    }

    /* Last section */
    section = mk_list_entry_last(head, struct mk_config_section, _head);

    /* Alloc new entry */
    new = mk_mem_malloc(sizeof(struct mk_config_entry));
    new->key = mk_string_dup(key);
    new->val = mk_string_dup(val);

    mk_list_add(&new->_head, &section->entries);
}

struct mk_config *mk_config_create(const char *path)
{
    int i;
    int len;
    int line = 0;
    int indent_len = -1;
    int n_keys = 0;
    char buf[255];
    char *section = NULL;
    char *indent = NULL;
    char *key, *val;
    struct mk_config *conf = NULL;
    struct mk_config_section *current = NULL;
    FILE *f;

    /* Open configuration file */
    if ((f = fopen(path, "r")) == NULL) {
        mk_warn("Config: I cannot open %s file", path);
        return NULL;
    }

    /* Alloc configuration node */
    conf = mk_mem_malloc_z(sizeof(struct mk_config));
    conf->created = time(NULL);
    conf->file = mk_string_dup(path);
    mk_list_init(&conf->sections);

    /* looking for configuration directives */
    while (fgets(buf, 255, f)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
            }
        }

        /* Line number */
        line++;

        if (!buf[0]) {
            continue;
        }

        /* Skip commented lines */
        if (buf[0] == '#') {
            continue;
        }

        /* Section definition */
        if (buf[0] == '[') {
            int end = -1;
            end = mk_string_char_search(buf, ']', len);
            if (end > 0) {
                /*
                 * Before to add a new section, lets check the previous
                 * one have at least one key set
                 */
                if (current && n_keys == 0) {
                    mk_config_warning(path, line, "Previous section did not have keys");
                }

                /* Create new section */
                section = mk_string_copy_substr(buf, 1, end);
                current = mk_config_section_add(conf, section);
                mk_mem_free(section);
                n_keys = 0;
                continue;
            }
            else {
                mk_config_error(path, line, "Bad header definition");
            }
        }

        /* No separator defined */
        if (!indent) {
            i = 0;

            do { i++; } while (i < len && isblank(buf[i]));

            indent = mk_string_copy_substr(buf, 0, i);
            indent_len = strlen(indent);

            /* Blank indented line */
            if (i == len) {
                continue;
            }
        }


        /* Validate indentation level */
        if (strncmp(buf, indent, indent_len) != 0 ||
            isblank(buf[indent_len]) != 0) {
            mk_config_error(path, line, "Invalid indentation level");
        }

        if (buf[indent_len] == '#' || indent_len == len) {
            continue;
        }

        /* Get key and val */
        i = mk_string_char_search(buf + indent_len, ' ', len - indent_len);
        key = mk_string_copy_substr(buf + indent_len, 0, i);
        val = mk_string_copy_substr(buf + indent_len + i, 1, len - indent_len - i);

        if (!key || !val || i < 0) {
            mk_config_error(path, line, "Each key must have a value");
        }

        /* Trim strings */
        mk_string_trim(&key);
        mk_string_trim(&val);

        /* Register entry: key and val are copied as duplicated */
        mk_config_entry_add(conf, key, val);

        /* Free temporal key and val */
        mk_mem_free(key);
        mk_mem_free(val);

        n_keys++;
    }

    if (section && n_keys == 0) {
        /* No key, no warning */
    }

    /*
    struct mk_config_section *s;
    struct mk_config_entry *e;

    s = conf->section;
    while(s) {
        printf("\n[%s]", s->name);
        e = s->entry;
        while(e) {
            printf("\n   %s = %s", e->key, e->val);
            e = e->next;
        }
        s = s->next;
    }
    fflush(stdout);
    */
    fclose(f);
    if (indent) mk_mem_free(indent);
    return conf;
}

void mk_config_free(struct mk_config *conf)
{
    struct mk_config_section *section;
    struct mk_list *head, *tmp;

    /* Free sections */
    mk_list_foreach_safe(head, tmp, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        mk_list_del(&section->_head);

        /* Free section entries */
        mk_config_free_entries(section);

        /* Free section node */
        mk_mem_free(section->name);
        mk_mem_free(section);
    }
    if (conf->file) mk_mem_free(conf->file);
    if (conf) mk_mem_free(conf);
}

void mk_config_free_entries(struct mk_config_section *section)
{
    struct mk_config_entry *entry;
    struct mk_list *head, *tmp;

    mk_list_foreach_safe(head, tmp, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);
        mk_list_del(&entry->_head);

        /* Free memory assigned */
        mk_mem_free(entry->key);
        mk_mem_free(entry->val);
        mk_mem_free(entry);
    }
}

void mk_config_listeners_free()
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_config_listener *l;

    mk_list_foreach_safe(head, tmp, &mk_config->listeners) {
        l = mk_list_entry(head, struct mk_config_listener, _head);
        mk_list_del(&l->_head);
        mk_mem_free(l->address);
        mk_mem_free(l->port);
        mk_mem_free(l);
    }
}

void mk_config_free_all()
{
    mk_vhost_free_all();
    mk_mimetype_free_all();

    if (mk_config->config) mk_config_free(mk_config->config);

    if (mk_config->serverconf) mk_mem_free(mk_config->serverconf);
    if (mk_config->pid_file_path) mk_mem_free(mk_config->pid_file_path);
    if (mk_config->user_dir) mk_mem_free(mk_config->user_dir);

    /* free config->index_files */
    if (mk_config->index_files) {
        mk_string_split_free(mk_config->index_files);
    }

    if (mk_config->user) mk_mem_free(mk_config->user);
    if (mk_config->transport_layer) mk_mem_free(mk_config->transport_layer);

    mk_config_listeners_free();

    mk_ptr_free(&mk_config->server_software);
    mk_mem_free(mk_config->plugins);
    mk_mem_free(mk_config);
}

void *mk_config_section_getval(struct mk_config_section *section, char *key, int mode)
{
    int on, off;
    struct mk_config_entry *entry;
    struct mk_list *head;

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);

        if (strcasecmp(entry->key, key) == 0) {
            switch (mode) {
            case MK_CONFIG_VAL_STR:
                return (void *) mk_string_dup(entry->val);
            case MK_CONFIG_VAL_NUM:
                return (void *) strtol(entry->val, (char **) NULL, 10);
            case MK_CONFIG_VAL_BOOL:
                on = strcasecmp(entry->val, VALUE_ON);
                off = strcasecmp(entry->val, VALUE_OFF);

                if (on != 0 && off != 0) {
                    return (void *) -1;
                }
                else if (on >= 0) {
                    return (void *) MK_TRUE;
                }
                else {
                    return (void *) MK_FALSE;
                }
            case MK_CONFIG_VAL_LIST:
                return (void *)mk_string_split_line(entry->val);
            }
        }
    }
    return NULL;
}

#ifndef SHAREDLIB

static void mk_details_listen(struct mk_list *listen)
{

    struct mk_list *head;
    struct mk_config_listener *l;

    mk_list_foreach(head, listen) {
        l = mk_list_entry(head, struct mk_config_listener, _head);
        printf(MK_BANNER_ENTRY "Server listening on %s:%s\n",
               l->address, l->port);
    }
}

void mk_details(void)
{
    printf(MK_BANNER_ENTRY "Process ID is %i\n", getpid());
    mk_details_listen(&mk_config->listeners);
    printf(MK_BANNER_ENTRY
           "%i threads, may handle up to %i client connections\n",
           mk_config->workers, mk_config->server_capacity);
    printf(MK_BANNER_ENTRY "Transport layer by %s in %s mode\n",
           mk_config->transport_layer_plugin->shortname,
           mk_config->transport);

#ifdef __linux__
    char tmp[64];

    if (mk_kernel_features_print(tmp, sizeof(tmp)) > 0) {
        printf(MK_BANNER_ENTRY "Linux Features: %s\n", tmp);
    }
#endif

    fflush(stdout);
}

/* Print a specific error */
static void mk_config_print_error_msg(char *variable, char *path)
{
    mk_err("Error in %s variable under %s, has an invalid value",
           variable, path);
    mk_mem_free(path);
    exit(EXIT_FAILURE);
}

/*
 * Check if at least one of the Listen interfaces are being used by another
 * process.
 */
int mk_config_listen_check_busy()
{
    int fd;
    struct mk_list *head;
    struct mk_config_listener *listen;

    mk_list_foreach(head, &mk_config->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);

        fd = mk_socket_connect(listen->address, atol(listen->port));
        if (fd != -1) {
            close(fd);
            return MK_TRUE;
        }
    }

    return MK_FALSE;
}

static int mk_config_listen_read(struct mk_config_section *section)
{
    long port_num;
    char *address = NULL;
    char *port = NULL;
    char *divider;
    struct mk_list *cur;
    struct mk_config_entry *entry;

    mk_list_foreach(cur, &section->entries) {
        entry = mk_list_entry(cur, struct mk_config_entry, _head);
        if (strcasecmp(entry->key, "Listen")) {
            continue;
        }

        if (entry->val[0] == '[') {
            // IPv6 address
            divider = strchr(entry->val, ']');
            if (divider == NULL) {
                mk_err("[config] Expected closing ']' in IPv6 address.");
                goto error;
            }
            if (divider[1] != ':' || divider[2] == '\0') {
                mk_err("[config] Expected ':port' after IPv6 address.");
                goto error;
            }

            address = mk_string_copy_substr(entry->val + 1, 0, divider - entry->val - 1);
            port = mk_string_dup(divider + 2);
        }
        else if (strchr(entry->val, ':') != NULL) {
            // IPv4 address
            divider = strrchr(entry->val, ':');
            if (divider == NULL || divider[1] == '\0') {
                mk_err("[config] Expected ':port' after IPv4 address.");
                goto error;
            }

            address = mk_string_copy_substr(entry->val, 0, divider - entry->val);
            port = mk_string_dup(divider + 1);
        }
        else {
            // Port only
            address = NULL;
            port = entry->val;
        }

        port_num = strtol(port, NULL, 10);
        if (errno != 0 || port_num == LONG_MAX || port_num == LONG_MIN) {
            mk_warn("Using defaults, could not understand \"Listen %s\"",
                    entry->val);
            port = NULL;
        }

        /* register the new listener */
        mk_config_listener_add(address, port);

error:
        if (address) mk_mem_free(address);
        if (port) mk_mem_free(port);
    }

    if (mk_list_is_empty(&mk_config->listeners) == 0) {
        mk_warn("[config] No valid Listen entries found, set default");
        mk_config_listener_add(NULL, NULL);
    }

    return 0;
}

/* Read configuration files */
static void mk_config_read_files(char *path_conf, char *file_conf)
{
    unsigned long len;
    char *tmp = NULL;
    struct stat checkdir;
    struct mk_config *cnf;
    struct mk_config_section *section;

    mk_config->serverconf = mk_string_dup(path_conf);

    if (stat(mk_config->serverconf, &checkdir) == -1) {
        mk_err("ERROR: Cannot find/open '%s'", mk_config->serverconf);
        exit(EXIT_FAILURE);
    }

    mk_string_build(&tmp, &len, "%s/%s", path_conf, file_conf);
    cnf = mk_config_create(tmp);
    if (!cnf) {
        mk_mem_free(tmp);
        mk_err("Cannot read '%s'", mk_config->server_conf_file);
        exit(EXIT_FAILURE);
    }
    section = mk_config_section_get(cnf, "SERVER");
    if (!section) {
        mk_err("ERROR: No 'SERVER' section defined");
        exit(EXIT_FAILURE);
    }

    /* Map source configuration */
    mk_config->config = cnf;

    /* Listen */
    if (!mk_config->port_override) {
        if (mk_config_listen_read(section)) {
            mk_err("[config] Failed to read listen sections.");
        }
    }
    else {
        mk_config_listener_add(NULL, mk_config->port_override);
    }

    /* Number of thread workers */
    if (mk_config->workers == -1) {
        mk_config->workers = (size_t) mk_config_section_getval(section,
                                                               "Workers",
                                                               MK_CONFIG_VAL_NUM);
    }

    if (mk_config->workers < 1) {
        mk_config->workers = sysconf(_SC_NPROCESSORS_ONLN);
        if (mk_config->workers < 1) {
            mk_config_print_error_msg("Workers", tmp);
        }
    }

    /* Timeout */
    mk_config->timeout = (size_t) mk_config_section_getval(section,
                                                           "Timeout", MK_CONFIG_VAL_NUM);
    if (mk_config->timeout < 1) {
        mk_config_print_error_msg("Timeout", tmp);
    }

    /* KeepAlive */
    mk_config->keep_alive = (size_t) mk_config_section_getval(section,
                                                              "KeepAlive",
                                                              MK_CONFIG_VAL_BOOL);
    if (mk_config->keep_alive == MK_ERROR) {
        mk_config_print_error_msg("KeepAlive", tmp);
    }

    /* MaxKeepAliveRequest */
    mk_config->max_keep_alive_request = (size_t)
        mk_config_section_getval(section,
                                 "MaxKeepAliveRequest",
                                 MK_CONFIG_VAL_NUM);

    if (mk_config->max_keep_alive_request == 0) {
        mk_config_print_error_msg("MaxKeepAliveRequest", tmp);
    }

    /* KeepAliveTimeout */
    mk_config->keep_alive_timeout = (size_t) mk_config_section_getval(section,
                                                                      "KeepAliveTimeout",
                                                                      MK_CONFIG_VAL_NUM);
    if (mk_config->keep_alive_timeout == 0) {
        mk_config_print_error_msg("KeepAliveTimeout", tmp);
    }

    /* Pid File */
    mk_config->pid_file_path = mk_config_section_getval(section,
                                                     "PidFile", MK_CONFIG_VAL_STR);

    /* Home user's directory /~ */
    mk_config->user_dir = mk_config_section_getval(section,
                                                "UserDir", MK_CONFIG_VAL_STR);

    /* Index files */
    mk_config->index_files = mk_config_section_getval(section,
                                                   "Indexfile", MK_CONFIG_VAL_LIST);

    /* HideVersion Variable */
    mk_config->hideversion = (size_t) mk_config_section_getval(section,
                                                         "HideVersion",
                                                         MK_CONFIG_VAL_BOOL);
    if (mk_config->hideversion == MK_ERROR) {
        mk_config_print_error_msg("HideVersion", tmp);
    }

    /* User Variable */
    mk_config->user = mk_config_section_getval(section, "User", MK_CONFIG_VAL_STR);

    /* Resume */
    mk_config->resume = (size_t) mk_config_section_getval(section,
                                                    "Resume", MK_CONFIG_VAL_BOOL);
    if (mk_config->resume == MK_ERROR) {
        mk_config_print_error_msg("Resume", tmp);
    }

    /* Max Request Size */
    mk_config->max_request_size = (size_t) mk_config_section_getval(section,
                                                              "MaxRequestSize",
                                                              MK_CONFIG_VAL_NUM);
    if (mk_config->max_request_size <= 0) {
        mk_config_print_error_msg("MaxRequestSize", tmp);
    }
    else {
        mk_config->max_request_size *= 1024;
    }

    /* Symbolic Links */
    mk_config->symlink = (size_t) mk_config_section_getval(section,
                                                     "SymLink", MK_CONFIG_VAL_BOOL);
    if (mk_config->symlink == MK_ERROR) {
        mk_config_print_error_msg("SymLink", tmp);
    }

    /* Transport Layer plugin */
    if (!mk_config->transport_layer) {
        mk_config->transport_layer = mk_config_section_getval(section,
                                                           "TransportLayer",
                                                           MK_CONFIG_VAL_STR);
    }

    /* Default Mimetype */
    mk_mem_free(tmp);
    tmp = mk_config_section_getval(section, "DefaultMimeType", MK_CONFIG_VAL_STR);
    if (!tmp) {
        mk_config->default_mimetype = mk_string_dup(MIMETYPE_DEFAULT_TYPE);
    }
    else {
        mk_string_build(&mk_config->default_mimetype, &len, "%s\r\n", tmp);
    }

    /* File Descriptor Table (FDT) */
    mk_config->fdt = (size_t) mk_config_section_getval(section,
                                                    "FDT",
                                                    MK_CONFIG_VAL_BOOL);

    /* FIXME: Overcapacity not ready */
    mk_config->fd_limit = (size_t) mk_config_section_getval(section,
                                                           "FDLimit",
                                                           MK_CONFIG_VAL_NUM);
    /* Get each worker clients capacity based on FDs system limits */
    mk_config->server_capacity = mk_server_capacity();


    if (!mk_config->one_shot) {
        mk_vhost_init(path_conf);
    }
    else {
        mk_vhost_set_single(mk_config->one_shot);
    }

    /* Server Signature */
    if (mk_config->hideversion == MK_FALSE) {
        snprintf(mk_config->server_signature,
                 sizeof(mk_config->server_signature) - 1,
                 "Monkey/%s", VERSION);
    }
    else {
        snprintf(mk_config->server_signature,
                 sizeof(mk_config->server_signature) - 1,
                 "Monkey");
    }
    len = snprintf(mk_config->server_signature_header,
                   sizeof(mk_config->server_signature_header) - 1,
                   "Server: %s\r\n", mk_config->server_signature);
    mk_config->server_signature_header_len = len;

    mk_mem_free(tmp);
}

/* read main configuration from monkey.conf */
void mk_config_start_configure(void)
{
    unsigned long len;

    mk_config_set_init_values();
    mk_config_read_files(mk_config->path_config, mk_config->server_conf_file);

    /* Load mimes */
    mk_mimetype_read_config();

    mk_ptr_reset(&mk_config->server_software);

    /* Basic server information */
    if (mk_config->hideversion == MK_FALSE) {
        mk_string_build(&mk_config->server_software.data,
                        &len, "Monkey/%s (%s)", VERSION, OS);
        mk_config->server_software.len = len;
    }
    else {
        mk_string_build(&mk_config->server_software.data, &len, "Monkey Server");
        mk_config->server_software.len = len;
    }
}

#endif // !SHAREDLIB

/* Register a new listener into the main configuration */
struct mk_config_listener *mk_config_listener_add(char *address, char *port)
{
    struct mk_list *head;
    struct mk_config_listener *check;
    struct mk_config_listener *listen = NULL;

    listen = mk_mem_malloc(sizeof(struct mk_config_listener));
    if (!listen) {
        mk_err("[listen_add] malloc() failed");
        return NULL;
    }

    if (!address) {
        listen->address = mk_string_dup(MK_DEFAULT_LISTEN_ADDR);
    }
    else {
        listen->address = mk_string_dup(address);
    }

    /* Set the port */
    if (!port) {
        listen->port = mk_string_dup(MK_DEFAULT_LISTEN_PORT);
    }
    else {
        listen->port = mk_string_dup(port);
    }

    /* Before to add a new listener, lets make sure it's not a duplicated */
    mk_list_foreach(head, &mk_config->listeners) {
        check = mk_list_entry(head, struct mk_config_listener, _head);
        if (strcmp(listen->address, check->address) == 0 &&
            strcmp(listen->port, check->port) == 0) {
            mk_warn("Listener: duplicated %s:%s, skip.",
                    listen->address, listen->port);

            /* free resources */
            mk_mem_free(listen->address);
            mk_mem_free(listen->port);
            mk_mem_free(listen);
            return NULL;
        }
    }

    mk_list_add(&listen->_head, &mk_config->listeners);
    return listen;
}

void mk_config_set_init_values(void)
{
    /* Init values */
    mk_config->is_seteuid = MK_FALSE;
    mk_config->timeout = 15;
    mk_config->hideversion = MK_FALSE;
    mk_config->keep_alive = MK_TRUE;
    mk_config->keep_alive_timeout = 15;
    mk_config->max_keep_alive_request = 50;
    mk_config->resume = MK_TRUE;
    mk_config->standard_port = 80;
    mk_config->symlink = MK_FALSE;
    mk_config->nhosts = 0;
    mk_list_init(&mk_config->hosts);
    mk_config->user = NULL;
    mk_config->open_flags = O_RDONLY | O_NONBLOCK;
    mk_config->index_files = NULL;
    mk_config->user_dir = NULL;

    /* TCP REUSEPORT: available on Linux >= 3.9 */
    if (mk_config->kernel_features & MK_KERNEL_SO_REUSEPORT) {
        mk_config->scheduler_mode = MK_SCHEDULER_REUSEPORT;
    }
    else {
        mk_config->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
    }

    /* TCP Auto Corking: only available on Linux >= 3.14 */
    if (mk_config->kernel_features & MK_KERNEL_TCP_AUTOCORKING) {
        mk_config->manual_tcp_cork = MK_FALSE;
    }
    else {
        mk_config->manual_tcp_cork = MK_TRUE;
    }

    /* Max request buffer size allowed
     * right now, every chunk size is 4KB (4096 bytes),
     * so we are setting a maximum request size to 32 KB */
    mk_config->max_request_size = MK_REQUEST_CHUNK * 8;

    /* Plugins */
    mk_config->plugins = mk_mem_malloc(sizeof(struct mk_list));

    /* Internals */
    mk_config->safe_event_write = MK_FALSE;

    /*
     * Transport type: useful to build redirection headers, values:
     *
     *   MK_TRANSPORT_HTTP
     *   MK_TRANSPORT_HTTPS
     *
     * we set default to 'http'
     */
    mk_config->transport = MK_TRANSPORT_HTTP;

    /* Init plugin list */
    mk_list_init(mk_config->plugins);

    /* Init listeners */
    mk_list_init(&mk_config->listeners);
}


void mk_config_sanity_check()
{
    /* Check O_NOATIME for current user, flag will just be used
     * if running user is allowed to.
     */
    int fd, flags = mk_config->open_flags;

    flags |= O_NOATIME;
    fd = open(mk_config->path_config, flags);

    if (fd > -1) {
        mk_config->open_flags = flags;
        close(fd);
    }
}
