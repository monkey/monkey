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
#include <ctype.h>

#include "monkey.h"
#include "config.h"
#include "str.h"
#include "utils.h"
#include "mimetype.h"
#include "info.h"
#include "logfile.h"
#include "memory.h"
#include "plugin.h"

/* Raise a configuration error */
void mk_config_error(const char *path, int line, const char *msg)
{
    printf("\nReading %s", path);
    printf("\nError in line %i: %s\n\n", line, msg);
    fflush(stdout);
    exit(1);
}

/* Returns a configuration section by [section name] */
struct mk_config_section *mk_config_section_get(struct mk_config *conf, 
                                                const char *section_name)
{
    struct mk_config_section *section;

    section = conf->section;
    while (section) {
        if (strcasecmp(section->name, section_name) == 0) {
            return section;
        }
        section = section->next;
    }

    return NULL;
}

/* Register a new section into the configuration struct */
void mk_config_section_add(struct mk_config *conf, char *section_name)
{
    struct mk_config_section *new, *aux;

    /* Alloc section node */
    new = mk_mem_malloc(sizeof(struct mk_config_section));
    new->name = section_name;
    new->entry = NULL;
    new->next = NULL;
    
    if (!conf->section) { 
        conf->section = new;
        return;
    }

    /* go to last section available */
    aux = conf->section;
    while (aux->next) {
        aux = aux->next;
    }

    aux->next = new;
    return;
}

/* Register a key/value entry in the last section available of the struct */
void mk_config_entry_add(struct mk_config *conf, 
                         const char *key, const char *val)
{
    struct mk_config_section *section;
    struct mk_config_entry *aux_entry, *new_entry;

    if (!conf->section) {
        puts("Error: there are not sections available!");
        exit(1);
    }

    /* Go to last section */
    section = conf->section;
    while (section->next) {
        section = section->next;
    }

    /* Alloc new entry */
    new_entry = mk_mem_malloc(sizeof(struct mk_config_entry));
    new_entry->key = mk_string_dup(key);
    new_entry->val = mk_string_dup(val);
    new_entry->next = NULL;

    /* Add first entry */
    if (!section->entry) {
        section->entry = new_entry;
        return;
    }

    /* Go to last entry */
    aux_entry = section->entry;
    while (aux_entry->next) {
        aux_entry = aux_entry->next;
    }

    aux_entry->next = new_entry;
}

struct mk_config *mk_config_create(const char *path)
{
    int len;
    int line = 0;
    int indent_len = -1;
    char buf[255];
    char *section = 0;
    char *indent = 0;
    char *key, *val, *last;
    struct mk_config *conf = 0;
    FILE *f;

    /* Open configuration file */
    if ((f = fopen(path, "r")) == NULL) {
        fprintf(stderr, "\nConfig Error: I can't open %s file\n\n", path);
        exit(1);
    }

    /* Alloc configuration node */
    conf = mk_mem_malloc(sizeof(struct mk_config));
    conf->created = time(NULL);
    conf->file = mk_string_dup(path);
    conf->section = NULL;

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
            if (section) {
                mk_mem_free(section);
                section = NULL;
            }
            continue;
        }

        /* Section definition */
        if (buf[0] == '[') {
            int end = -1;
            end = mk_string_char_search(buf, ']', len);
            if (end > 0) {
                section = mk_string_copy_substr(buf, 1, end);
                mk_config_section_add(conf, section);
                continue;
            }
            else {
                mk_config_error(path, line, "Bad header definition");
            }
        }
        else {
            /* No separator defined */
            if (!indent) {
                int i = 0;

                do { i++; } while (i < len && isblank(buf[i]));

                indent = mk_string_copy_substr(buf, 0, i);
                indent_len = strlen(indent);

                /* Blank indented line */
                if (i == len) {
                    continue;
                }
            }

            /* Validate indentation level */
            if (strncmp(buf, indent, indent_len) != 0 || !section || 
                isblank(buf[indent_len]) != 0) {
                mk_config_error(path, line, "Invalid indentation level");
            }

            if (buf[indent_len] == '#' || indent_len == len) {
                continue;
            }

            /* get line key and value */
            key = strtok_r(buf + indent_len, "\"\t ", &last);
            val = strtok_r(NULL, "\"\t", &last); 

            if (!key || !val) {
                mk_config_error(path, line, "Each key must have a value");
                continue;
            }

            /* Register entry */
            mk_config_entry_add(conf, key, val);
        }
    }

    /*
    struct mk_config *t;
    struct mk_config_entry *e;

    t = conf;
    while(t) {
        printf("\n[%s]", t->header);
        e = t->entry;
        while(e) {
            printf("\n   %s = %s", e->key, e->val);
            e = e->next;
        }
        t = t->next;
    }
    fflush(stdout);
    */

    fclose(f);
    return conf;
}

void mk_config_free(struct mk_config *conf)
{
    struct mk_config_section *prev=0, *section;

    /* Free sections */
    section = conf->section;
    while (section) {
        while (section->next) {
            prev = section;
            section = section->next;
        }

        /* Free section entries */
        mk_config_free_entries(section);

        /* Free section node */
        mk_mem_free(section->name);
        mk_mem_free(section);

        if (section == conf->section) {
            return;
        }
        prev->next = NULL;
        section = conf->section;
    }
}

void mk_config_free_entries(struct mk_config_section *section)
{
    struct mk_config_entry *prev = 0, *target;

    target = section->entry;
    while (target) {
        while (target->next) {
            prev = target;
            target = target->next;
        }

        /* Free memory assigned */
        mk_mem_free(target->key);
        mk_mem_free(target->val);

        if (target == section->entry) {
            section->entry = NULL;
            return;
        }

        prev->next = NULL;
        target = section->entry;
    }
}

void *mk_config_section_getval(struct mk_config_section *section, char *key, int mode)
{
    int on, off;
    struct mk_config_entry *entry;

    entry = section->entry;
    while (entry) {
        if (strcasecmp(entry->key, key) == 0) {
            switch (mode) {
            case MK_CONFIG_VAL_STR:
                return (void *) entry->val;
            case MK_CONFIG_VAL_NUM:
                return (void *) atoi(entry->val);
            case MK_CONFIG_VAL_BOOL:
                on = strcasecmp(entry->val, VALUE_ON);
                off = strcasecmp(entry->val, VALUE_OFF);

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
                return mk_string_split_line(entry->val);
            }
        }
        else {
            entry = entry->next;
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
    struct mk_config_section *section;
    struct mk_string_line *line, *line_val;

    config->serverconf = mk_string_dup(path_conf);
    config->workers = MK_WORKERS_DEFAULT;

    if (stat(config->serverconf, &checkdir) == -1) {
        fprintf(stderr, "\nERROR: Invalid path to configuration files");
        fprintf(stderr, "\nCannot find/open '%s'\n", config->serverconf);
        exit(1);
    }

    mk_string_build(&path, &len, "%s/%s", path_conf, file_conf);

    cnf = mk_config_create(path);
    section = mk_config_section_get(cnf, "SERVER");

    /* Map source configuration */
    config->_config = cnf;

    /* Listen */
    config->listen_addr = mk_config_section_getval(section, "Listen", 
                                                   MK_CONFIG_VAL_STR);
    if (!config->listen_addr) {
        config->listen_addr = MK_DEFAULT_LISTEN_ADDR;
    }

    /* Connection port */
    config->serverport = (int) mk_config_section_getval(section,
                                                        "Port", 
                                                        MK_CONFIG_VAL_NUM);
    if (!config->serverport >= 1 && !config->serverport <= 65535) {
        mk_config_print_error_msg("Port", path);
    }

    /* Number of thread workers */
    config->workers = (int) mk_config_section_getval(section,
                                                     "Workers", 
                                                     MK_CONFIG_VAL_NUM);
    if (config->maxclients < 1) {
        mk_config_print_error_msg("Workers", path);
    }

    /* Timeout */
    config->timeout = (int) mk_config_section_getval(section,
                                                     "Timeout", MK_CONFIG_VAL_NUM);
    if (config->timeout < 1) {
        mk_config_print_error_msg("Timeout", path);
    }
    
    /* KeepAlive */
    config->keep_alive = (int) mk_config_section_getval(section,
                                                        "KeepAlive",
                                                        MK_CONFIG_VAL_BOOL);
    if (config->keep_alive == VAR_ERR) {
        mk_config_print_error_msg("KeepAlive", path);
    }

    /* MaxKeepAliveRequest */
    config->max_keep_alive_request = (int)
        mk_config_section_getval(section,
                                 "MaxKeepAliveRequest",
                                 MK_CONFIG_VAL_NUM);
    
    if (config->max_keep_alive_request == 0) {
        mk_config_print_error_msg("MaxKeepAliveRequest", path);
    }

    /* KeepAliveTimeout */
    config->keep_alive_timeout = (int) mk_config_section_getval(section,
                                                                "KeepAliveTimeout",
                                                                MK_CONFIG_VAL_NUM);
    if (config->keep_alive_timeout == 0) {
        mk_config_print_error_msg("KeepAliveTimeout", path);
    }

    /* Pid File */
    config->pid_file_path = mk_config_section_getval(section,
                                                     "PidFile", MK_CONFIG_VAL_STR);
    
    /* Home user's directory /~ */
    config->user_dir = mk_config_section_getval(section, 
                                                "UserDir", MK_CONFIG_VAL_STR);

    /* Index files */
    line_val = line = mk_config_section_getval(section,
                                               "Indexfile", MK_CONFIG_VAL_LIST);
    while (line_val != NULL) {
        mk_config_add_index(line_val->val);
        line_val = line_val->next;
    }

    /* HideVersion Variable */
    config->hideversion = (int) mk_config_section_getval(section,
                                                         "HideVersion",
                                                         MK_CONFIG_VAL_BOOL);
    if (config->hideversion == VAR_ERR) {
        mk_config_print_error_msg("HideVersion", path);
    }

    /* User Variable */
    config->user = mk_config_section_getval(section, "User", MK_CONFIG_VAL_STR);

    /* Resume */
    config->resume = (int) mk_config_section_getval(section,
                                                    "Resume", MK_CONFIG_VAL_BOOL);
    if (config->resume == VAR_ERR) {
        mk_config_print_error_msg("Resume", path);
    }

    /* Symbolic Links */
    config->symlink = (int) mk_config_section_getval(section,
                                                     "SymLink", MK_CONFIG_VAL_BOOL);
    if (config->symlink == VAR_ERR) {
        mk_config_print_error_msg("SymLink", path);
    }
    
    mk_mem_free(path);
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

    mk_string_build(&buf, &len, "%s/sites/default", path);
    config->hosts = mk_config_get_host(buf);
    config->nhosts++;
    mk_mem_free(buf);

    if (!config->hosts) {
        printf("\nError parsing main configuration file 'default'\n");
        exit(1);
    }

    mk_string_build(&buf, &len, "%s/sites/", path);
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

        mk_string_build(&file, &len, "%s/sites/%s", path, ent->d_name);

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
    struct mk_config_section *section;

    /* Read configuration file */
    cnf = mk_config_create(path);

    /* Read tag 'HOST' */
    section = mk_config_section_get(cnf, "HOST");

    /* Alloc configuration node */
    host = mk_mem_malloc_z(sizeof(struct host));
    host->config = cnf;
    host->file = mk_string_dup(path);
    host->servername = mk_config_section_getval(section, "Servername", 
                                                MK_CONFIG_VAL_STR);

    /* document root handled by a mk_pointer */
    host->documentroot.data = mk_config_section_getval(section,
                                                       "DocumentRoot",
                                                       MK_CONFIG_VAL_STR);
    host->documentroot.len = strlen(host->documentroot.data);

    /* validate document root configured */
    if (stat(host->documentroot.data, &checkdir) == -1) {
        fprintf(stderr, "ERROR: Invalid path to DocumentRoot in %s\n\n", path);
        exit(1);
    }
    else if (!(checkdir.st_mode & S_IFDIR)) {
        fprintf(stderr,
                "ERROR: DocumentRoot variable in %s has an invalid directory path\n\n",
                path);
        exit(1);
    }

    if (!host->servername) {
        mk_config_free(cnf);
        return NULL;
    }

    /* Server Signature */
    if (config->hideversion == VAR_OFF) {
        mk_string_build(&host->host_signature, &len,
                        "Monkey/%s", VERSION);
    }
    else {
        mk_string_build(&host->host_signature, &len, "Monkey");
    }
    mk_string_build(&host->header_host_signature.data,
                    &host->header_host_signature.len,
                    "Server: %s", host->host_signature);


    /* Access log */
    host->access_log_path = mk_config_section_getval(section,
                                                     "AccessLog", 
                                                     MK_CONFIG_VAL_STR);
    /* Error log */
    host->error_log_path = mk_config_section_getval(section,
                                                    "ErrorLog", 
                                                    MK_CONFIG_VAL_STR);
    host->next = NULL;
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
    config->plugins = NULL;
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
        mk_string_build(&config->server_software.data,
                        &len, "Monkey/%s (%s)", VERSION, OS);
        config->server_software.len = len;
    }
    else {
        mk_string_build(&config->server_software.data, &len, "Monkey Server");
        config->server_software.len = len;
    }
}

struct host *mk_config_host_find(mk_pointer host)
{
    struct host *aux_host;

    aux_host = config->hosts;

    while (aux_host) {
        if (strncasecmp(aux_host->servername, host.data, host.len) == 0) {
            return aux_host;
        }
        aux_host = aux_host->next;
    }

    return NULL;
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
