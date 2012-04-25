/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <dirent.h>

#include "MKPlugin.h"
#include "duda_session.h"
#include "duda.h"
#include "webservice.h"
#include "duda_conf.h"

struct duda_api_session *duda_session_object()
{
    struct duda_api_session *s;

    s = mk_api->mem_alloc(sizeof(struct duda_api_session));
    s->init    = duda_session_init;
    s->create  = duda_session_create;
    s->destroy = duda_session_destroy;
    s->get     = duda_session_get;
    s->isset   = duda_session_isset;

    return s;
}

/*
 * Duda sessions are stored into /dev/shm, yes, we know that is not expected as
 * the main purpose of /dev/shm is for process intercommunication and we are breaking
 * the rule. Mount a filesystem before launch the service is an extra step, do that
 * inside Duda will generate permission issues.. so ?, we use /dev/shm.
 */
int _duda_session_create_store(const char *path)
{
    int ret;

    ret = mkdir(path, SESSION_DEFAULT_PERM);
    if (ret != 0) {
        mk_err("duda_session: could not create SESSION_STORE_PATH '%s'", SESSION_STORE_PATH);
        return -1;
    }

    return 0;
}

/* Initialize a duda session for the webservice in question */
int duda_session_init()
{
    int ret;
    char *path = NULL;
    unsigned long len;
    struct file_info finfo;
    /*
     * FIXME: we are using a fixed store_name, the name must be equal to the
     * webservice in question
     */
    char *store_name = "fixme";

    ret = mk_api->file_get_info(SESSION_STORE_PATH, &finfo);
    if (ret != 0) {
        if (_duda_session_create_store(SESSION_STORE_PATH) != 0) {
            return -1;
        }
    }

    mk_api->str_build(&path, &len, "%s/%s", SESSION_STORE_PATH, store_name);
    ret = mk_api->file_get_info(path, &finfo);
    if (ret != 0) {
        if (_duda_session_create_store(path) != 0) {
            return -1;
        }
    }

    return 0;
}


static inline int _rand(int entropy)
{
    struct timeval tm;

    gettimeofday(&tm, NULL);
    srand(tm.tv_usec + entropy);

    return rand();
}

/* FIXME: It must check for duplicates */
int duda_session_create(duda_request_t *dr, char *name, char *value, int expires)
{
    long e;
    int n, fd, len;
    char *uuid;
    char session[SESSION_UUID_SIZE];
    //struct web_service *ws = dr->ws_root;

    /*
     * generate some random value, lets give some entropy and
     * then generate the UUID to send the proper Cookie to the
     * client.
     */
    e = ((long) &dr) + ((long) &dr->cs) + (dr->cs->socket);
    uuid = mk_api->mem_alloc(SESSION_UUID_SIZE);
    if (!uuid) {
        mk_warn("duda_session: could not allocate space for UUID");
        return -1;
    }

    len = snprintf(uuid, SESSION_UUID_SIZE, "%x-%x",
                   _rand(e), _rand(e));
    duda_cookie_set(dr, "DUDA_SESSION", 12, uuid, len, expires);

    /* session format: expire_time.name.UUID.duda_session */
    snprintf(session, SESSION_UUID_SIZE, "%s/%s.%s.%d",
             SESSION_STORE_PATH, name, uuid, expires);
    fd = open(session, O_CREAT | O_WRONLY, 0600);
    if (fd == -1) {
        perror("open");
        mk_err("duda_session: could not create session file");
        return -1;
    }

    n = write(fd, value, strlen(value));
    close(fd);

    if (n == -1) {
        mk_err("duda_session: could not write to session file");
        return -1;
    }

    return 0;
}

int _duda_session_get_path(duda_request_t *dr, char *name, char **buffer, int buf_size)
{
    int ret;
    int len;
    int buf_len;
    char buf[SESSION_UUID_SIZE];
    char *session_val;
    DIR *dir;
    struct dirent *ent;

    /* Get UUID for the specified key */
    ret = duda_cookie_get(dr, SESSION_KEY, &session_val, &len);
    if (ret == -1) {
        return -1;
    }

    /* Open store path */
    if (!(dir = opendir(SESSION_STORE_PATH))) {
        return -1;
    }

    /* Compose possible session file name */
    memset(buf, '\0', sizeof(buf));
    ret = snprintf(buf, SESSION_UUID_SIZE, "%s.", name);
    strncpy(buf + ret, session_val, len);
    buf_len = ret + len;
    buf[buf_len++] = '.';
    buf[buf_len  ] = '\0';

    /* Go into session files */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') && (strcmp(ent->d_name, "..") != 0)) {
            continue;
        }

        /* Look just for files */
        if (ent->d_type != DT_REG) {
            continue;
        }

        /* try to match the file name */
        if (strncmp(ent->d_name, buf, buf_len) == 0) {
            snprintf(*buffer, buf_size, "%s/%s", SESSION_STORE_PATH, ent->d_name);
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;
}

int duda_session_destroy(duda_request_t *dr, char *name)
{
    int ret;
    char *buf = mk_api->mem_alloc(SESSION_UUID_SIZE);

    /* Get the absolute path for the session file */
    ret = _duda_session_get_path(dr, name, &buf, SESSION_UUID_SIZE);
    if (ret == 0) {
        unlink(buf);
    }

    mk_api->mem_free(buf);

    /* Now lets make the client cookie expire */
    duda_cookie_destroy(dr, SESSION_KEY, sizeof(SESSION_KEY) - 1);
    return ret;
}

void *duda_session_get(duda_request_t *dr, char *name)
{
    int ret;
    char *buf = mk_api->mem_alloc(SESSION_UUID_SIZE);
    char *raw;

    /* We need to catch the right UUID for the session in question */
    ret = _duda_session_get_path(dr, name, &buf, SESSION_UUID_SIZE);
    if (ret == -1) {
        return NULL;
    }

    raw = mk_api->file_to_buffer(buf);
    mk_api->mem_free(buf);
    return raw;
}

int duda_session_isset(duda_request_t *dr, char *name)
{
    int ret;
    int len;
    int buf_len;
    char buf[SESSION_UUID_SIZE];
    char *session_val;
    DIR *dir;
    struct dirent *ent;

    /* Get UUID for the specified key */
    ret = duda_cookie_get(dr, SESSION_KEY, &session_val, &len);
    if (ret == -1) {
        return -1;
    }

    /* Open store path */
    if (!(dir = opendir(SESSION_STORE_PATH))) {
        return -1;
    }

    /* Compose possible session file name */
    memset(buf, '\0', sizeof(buf));
    ret = snprintf(buf, SESSION_UUID_SIZE, "%s.", name);
    strncpy(buf + ret, session_val, len);
    buf_len = ret + len;
    buf[buf_len++] = '.';
    buf[buf_len  ] = '\0';

    /* Go into session files */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') && (strcmp(ent->d_name, "..") != 0)) {
            continue;
        }

        /* Look just for files */
        if (ent->d_type != DT_REG) {
            continue;
        }

        /* try to match the file name */
        if (strncmp(ent->d_name, buf, buf_len) == 0) {
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;
}
