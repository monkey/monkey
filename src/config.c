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

#include "monkey.h"
#include "config.h"
#include "str.h"
#include "utils.h"
#include "mimetype.h"
#include "info.h"
#include "logfile.h"
#include "memory.h"
#include "plugin.h"

struct mk_config *mk_config_create(char *path)
{
    FILE *f;
    int len;
    char buf[255];
    char *key = 0, *val = 0, *last = 0;
    struct mk_config *cnf = 0, *new, *p;

    if ((f = fopen(path, "r")) == NULL) {
        fprintf(stderr, "\nConfig Error: I can't open %s file\n\n", path);
        exit(1);
    }

    /* looking for configuration directives */
    while (fgets(buf, 255, f)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r')
                buf[--len] = 0;
        }

        if (!buf[0] || buf[0] == '#')
            continue;

        key = strtok_r(buf, "\"\t ", &last);
        val = strtok_r(NULL, "\"\t ", &last);

        if (!key || !val) {
            continue;
        }

        /* Allow new entry found */
        new = mk_mem_malloc(sizeof(struct mk_config));
        new->key = mk_string_dup(key);

        new->val = mk_string_dup(val);
        new->next = NULL;

        /* Link to main list */
        if (!cnf) {
            cnf = new;
        }
        else {
            p = cnf;
            while (p->next) {
                p = p->next;
            }
            p->next = new;
        }
    }

    fclose(f);
    return cnf;
}

void mk_config_free(struct mk_config *cnf)
{
    struct mk_config *prev = 0, *target;

    target = cnf;
    while (target) {
        while (target->next) {
            prev = target;
            target = target->next;
        }

        mk_mem_free(target);

        if (target == cnf) {
            return;
        }
        prev->next = NULL;
        target = cnf;
    }
}

void *mk_config_getval(struct mk_config *cnf, char *key, int mode)
{
    int on, off;
    struct mk_config *p;

    p = cnf;
    while (p) {
        if (strcasecmp(p->key, key) == 0) {
            switch (mode) {
            case MK_CONFIG_VAL_STR:
                return (void *) p->val;
            case MK_CONFIG_VAL_NUM:
                return (void *) atoi(p->val);
            case MK_CONFIG_VAL_BOOL:
                on = strcasecmp(p->val, VALUE_ON);
                off = strcasecmp(p->val, VALUE_OFF);

                if (on != 0 && off != 0) {
                    return (void *) -1;
                }
                else if (on >= 0) {
                    return (void *) VAR_ON;
                }
                else {
                    return (void *) VAR_OFF;
                }
            case MK_CONFIG_VAL_LIST:
                return mk_string_split_line(p->val);
            }
        }
        else {
            p = p->next;
        }
    }
    return NULL;
}

/* Read configuration files */
void mk_config_read_files(char *path_conf, char *file_conf)
{
    unsigned long len;
    char *path = 0;
    struct stat checkdir;
    struct mk_config *cnf;
    struct mk_string_line *line, *line_val;

    config->serverconf = mk_string_dup(path_conf);
    config->workers = MK_WORKERS_DEFAULT;

    if (stat(config->serverconf, &checkdir) == -1) {
        fprintf(stderr, "ERROR: Invalid path to configuration files.");
        exit(1);
    }

    m_build_buffer(&path, &len, "%s/%s", path_conf, file_conf);

    cnf = mk_config_create(path);

    /* Listen */
    config->listen_addr = mk_config_getval(cnf, "Listen", MK_CONFIG_VAL_STR);
    if (!config->listen_addr) {
        config->listen_addr = MK_DEFAULT_LISTEN_ADDR;
    }

    /* Connection port */
    config->serverport = (int) mk_config_getval(cnf,
                                                "Port", MK_CONFIG_VAL_NUM);
    if (!config->serverport >= 1 && !config->serverport <= 65535) {
        mk_config_print_error_msg("Port", path);
    }

    /* Number of thread workers */
    config->workers = (int) mk_config_getval(cnf,
                                             "Workers", MK_CONFIG_VAL_NUM);
    if (config->maxclients < 1) {
        mk_config_print_error_msg("Workers", path);
    }

    /* Timeout */
    config->timeout = (int) mk_config_getval(cnf,
                                             "Timeout", MK_CONFIG_VAL_NUM);
    if (config->timeout < 1) {
        mk_config_print_error_msg("Timeout", path);
    }

    /* KeepAlive */
    config->keep_alive = (int) mk_config_getval(cnf,
                                                "KeepAlive",
                                                MK_CONFIG_VAL_BOOL);
    if (config->keep_alive == VAR_ERR) {
        mk_config_print_error_msg("KeepAlive", path);
    }

    /* MaxKeepAliveRequest */
    config->max_keep_alive_request = (int) mk_config_getval(cnf,
                                                            "MaxKeepAliveRequest",
                                                            MK_CONFIG_VAL_NUM);
    if (config->max_keep_alive_request == 0) {
        mk_config_print_error_msg("MaxKeepAliveRequest", path);
    }

    /* KeepAliveTimeout */
    config->keep_alive_timeout = (int) mk_config_getval(cnf,
                                                        "KeepAliveTimeout",
                                                        MK_CONFIG_VAL_NUM);
    if (config->keep_alive_timeout == 0) {
        mk_config_print_error_msg("KeepAliveTimeout", path);
    }

    /* Pid File */
    config->pid_file_path = mk_config_getval(cnf,
                                             "PidFile", MK_CONFIG_VAL_STR);

    /* Home user's directory /~ */
    config->user_dir = mk_config_getval(cnf, "UserDir", MK_CONFIG_VAL_STR);

    /* Index files */
    line_val = line = mk_config_getval(cnf, "Indexfile", MK_CONFIG_VAL_LIST);
    while (line_val != NULL) {
        mk_config_add_index(line_val->val);
        line_val = line_val->next;
    }

    /* HideVersion Variable */
    config->hideversion = (int) mk_config_getval(cnf,
                                                 "HideVersion",
                                                 MK_CONFIG_VAL_BOOL);
    if (config->hideversion == VAR_ERR) {
        mk_config_print_error_msg("HideVersion", path);
    }

    /* User Variable */
    config->user = mk_config_getval(cnf, "User", MK_CONFIG_VAL_STR);

    /* Resume */
    config->resume = (int) mk_config_getval(cnf,
                                            "Resume", MK_CONFIG_VAL_BOOL);
    if (config->resume == VAR_ERR) {
        mk_config_print_error_msg("Resume", path);
    }

    /* Symbolic Links */
    config->symlink = (int) mk_config_getval(cnf,
                                             "SymLink", MK_CONFIG_VAL_BOOL);
    if (config->symlink == VAR_ERR) {
        mk_config_print_error_msg("SymLink", path);
    }

    mk_mem_free(path);
    mk_config_free(cnf);
    mk_config_read_hosts(path_conf);
}

void mk_config_read_hosts(char *path)
{
    DIR *dir;
    unsigned long len;
    char *buf = 0;
    char *file;
    struct host *p_host, *new_host;     /* debug */
    struct dirent *ent;

    m_build_buffer(&buf, &len, "%s/sites/default", path);
    config->hosts = mk_config_get_host(buf);
    config->nhosts++;
    mk_mem_free(buf);

    if (!config->hosts) {
        printf("\nError parsing main configuration file 'default'\n");
        exit(1);
    }

    m_build_buffer(&buf, &len, "%s/sites/", path);
    if (!(dir = opendir(buf)))
        exit(1);


    p_host = config->hosts;

    /* Reading content */
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp((char *) ent->d_name, ".") == 0)
            continue;
        if (strcmp((char *) ent->d_name, "..") == 0)
            continue;
        if (strcasecmp((char *) ent->d_name, "default") == 0)
            continue;

        m_build_buffer(&file, &len, "%s/sites/%s", path, ent->d_name);

        new_host = (struct host *) mk_config_get_host(file);
        mk_mem_free(file);
        if (!new_host) {
            continue;
        }
        else {
            p_host->next = new_host;
            p_host = new_host;
            config->nhosts++;
        }
    }
    closedir(dir);
}

struct host *mk_config_get_host(char *path)
{
    unsigned long len = 0;
    struct stat checkdir;
    struct host *host;
    struct mk_config *cnf;

    cnf = mk_config_create(path);

    host = mk_mem_malloc_z(sizeof(struct host));
    host->servername = 0;
    host->file = mk_string_dup(path);

    host->servername = mk_config_getval(cnf, "Servername", MK_CONFIG_VAL_STR);
    host->documentroot.data = mk_config_getval(cnf,
                                               "DocumentRoot",
                                               MK_CONFIG_VAL_STR);
    host->documentroot.len = strlen(host->documentroot.data);
    if (stat(host->documentroot.data, &checkdir) == -1) {
        fprintf(stderr, "ERROR: Invalid path to Server_root in %s\n\n", path);
        exit(1);
    }
    else if (!(checkdir.st_mode & S_IFDIR)) {
        fprintf(stderr,
                "ERROR: DocumentRoot variable in %s has an invalid directory path\n\n",
                path);
        exit(1);
    }

    /* Access log */
    host->access_log_path = mk_config_getval(cnf,
                                             "AccessLog", MK_CONFIG_VAL_STR);
    /* Error log */
    host->error_log_path = mk_config_getval(cnf,
                                            "ErrorLog", MK_CONFIG_VAL_STR);

    /* Get directory */
    host->getdir = (int) mk_config_getval(cnf, "GetDir", MK_CONFIG_VAL_BOOL);
    if (host->getdir == VAR_ERR) {
        mk_config_print_error_msg("GetDir", path);
    }

    if (!host->servername) {
        mk_config_free(cnf);
        return NULL;
    }

    /* Server Signature */
    if (config->hideversion == VAR_OFF) {
        m_build_buffer(&host->host_signature, &len,
                       "Monkey/%s", VERSION);
    }
    else {
        m_build_buffer(&host->host_signature, &len, "Monkey");
    }
    m_build_buffer(&host->header_host_signature.data,
                   &host->header_host_signature.len,
                   "Server: %s", host->host_signature);

    if( host->access_log_path != NULL ) {
        if (pipe(host->log_access) < 0) {
            perror("pipe");
        } else {
            fcntl(host->log_access[1], F_SETFL, O_NONBLOCK);
        }
    }

    if( host->error_log_path != NULL ) {
        if (pipe(host->log_error) < 0) {
            perror("pipe");
        } else {
            fcntl(host->log_error[1], F_SETFL, O_NONBLOCK);
        }
    }

    host->next = NULL;
    mk_config_free(cnf);
    return host;
}

/* Imprime error de configuracion y cierra */
void mk_config_print_error_msg(char *variable, char *path)
{
    fprintf(stderr, "\nError: %s variable in %s has an invalid value.\n",
            variable, path);
    fflush(stderr);
    exit(1);
}

/* Agrega distintos index.xxx */
void mk_config_add_index(char *indexname)
{
    struct indexfile *new_index = 0, *aux_index;

    new_index = (struct indexfile *) malloc(sizeof(struct indexfile));
    strncpy(new_index->indexname, indexname, MAX_INDEX_NOMBRE - 1);
    new_index->indexname[MAX_INDEX_NOMBRE - 1] = '\0';
    new_index->next = NULL;

    if (first_index == NULL) {
        first_index = new_index;
    }
    else {
        aux_index = first_index;
        while (aux_index->next != NULL)
            aux_index = aux_index->next;
        aux_index->next = new_index;
    }
}

void mk_config_set_init_values(void)
{
    /* Valores iniciales */
    config->timeout = 15;
    config->hideversion = VAR_OFF;
    config->keep_alive = VAR_ON;
    config->keep_alive_timeout = 15;
    config->max_keep_alive_request = 50;
    config->maxclients = 150;
    config->max_ip = 15;
    config->resume = VAR_ON;
    config->standard_port = 80;
    config->listen_addr = MK_DEFAULT_LISTEN_ADDR;
    config->serverport = 2001;
    config->symlink = VAR_OFF;
    config->nhosts = 0;
    config->user = NULL;
    config->open_flags = O_RDONLY | O_NONBLOCK;

    /* Plugins */
    config->plugins = mk_mem_malloc_z(sizeof(struct plugin_stages));
}

/* read main configuration from monkey.conf */
void mk_config_start_configure(void)
{
    unsigned long len;

    mk_config_set_init_values();
    mk_config_read_files(config->file_config, M_DEFAULT_CONFIG_FILE);

    /* if not index names defined, set default */
    if (first_index == NULL) {
        mk_config_add_index("index.html");
    }

    /* Load mimes */
    mk_mimetype_read_config();

    /* Basic server information */
    if (config->hideversion == VAR_OFF) {
        m_build_buffer(&config->server_software.data,
                       &len, "Monkey/%s (%s)", VERSION, OS);
        config->server_software.len = len;
    }
    else {
        m_build_buffer(&config->server_software.data, &len, "Monkey Server");
        config->server_software.len = len;
    }
}

struct host *mk_config_host_find(mk_pointer host)
{
    struct host *aux_host;

    aux_host = config->hosts;

    while (aux_host) {
        if (strncasecmp(aux_host->servername, host.data, host.len) == 0)
            break;
        else
            aux_host = aux_host->next;
    }

    return aux_host;
}

void mk_config_sanity_check()
{
    /* Check O_NOATIME for current user, flag will just be used 
     * if running user is allowed to.
     */
    int fd, flags = config->open_flags;

    flags |= O_NOATIME;
    fd = open(config->file_config, flags);

    if (fd > -1) {
        config->open_flags = flags;
        close(fd);
    }
}
