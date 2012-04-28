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

#ifndef DUDA_API_H
#define DUDA_API_H

#include "mk_list.h"
#include "duda.h"
#include "duda_global.h"
#include "duda_cookie.h"
#include "duda_package.h"
#include "duda_console.h"

/* types of data */
typedef struct duda_interface duda_interface_t;
typedef struct duda_method duda_method_t;
typedef struct duda_param duda_param_t;
typedef void * duda_callback_t;

/* The basic web service information */
struct duda_webservice {
    char *app_name;
    char *app_path;
};

/* Interfaces of the web service */
struct duda_interface {
    char *uid;
    int   uid_len;

    /* interface methods */
    struct mk_list methods;

    /* mk_list */
    struct mk_list _head;
};

/* Methods associated to an interface */
struct duda_method {
    char *uid;
    int   uid_len;

    short int num_params;
    char *callback;
    void *(*cb_webservice) (duda_request_t *);
    void *(*cb_builtin)    (duda_request_t *);

    struct mk_list params;

    /* mk_list */
    struct mk_list _head;
};

/* Parameters: each method supports N parameters */
struct duda_param {
    char *name;
    short int max_len;

    /* mk_list */
    struct mk_list _head;
};

/*
 * API objects
 * ===========
 * We provide an useful and easy to understand API for the developer,
 * this is not so easy due to the language and server side nature, if
 * you are not ready to take this red pill, go and run to the NodeJS arms :P
 *
 * Monkey
 * ------
 * Object pointing to the original parent API which expose the Monkey
 * internal, here we have many useful functions to manage strings, memory,
 * configuration files, etc.
 *
 *
 * Map
 * ---
 * An object which provide methods to create the service map based on
 * interfaces, methods and parameters.
 *
 *
 * Message
 * -------
 * Provide methods to print different informative messages.
 *
 *
 * Response
 * --------
 * Methods to generate response data to the clien
 *
 *
 * Debug
 * -----
 * A set of methods to debug the web service
 *
 *
 * Params
 * ------
 * A set of methods to retrieve web service parameters
 *
 */

/* MONKEY object: monkey->x() */
struct plugin_api *monkey;

/* MAP specific Duda calls */
struct duda_api_main {
    duda_package_t *(*package_load) (const char *);
};

/* MAP object: map->x() */
struct duda_api_map {
    /* interface_ */
    duda_interface_t *(*interface_new) (char *);
    void (*interface_add_method) (duda_method_t *, duda_interface_t *);

    /* method_ */
    duda_method_t *(*method_new) (char *, char *, int);
    duda_method_t *(*method_builtin_new) (char *, void (*cb_builtin) (duda_request_t *),
                                          int n_params);

    void (*method_add_param) (duda_param_t *, duda_method_t *);

    /* param_ */
    duda_param_t *(*param_new) (char *, short int);
};

/* MSG object: msg->x() */
struct duda_api_msg {
    void (*info) (const char *, ...);
    void (*warn) (const char *, ...);
    void (*err)  (const char *, ...);
    void (*bug)  (const char *, ...);
};

/* RESPONSE object: response->x() */
struct duda_api_response {
    int (*http_status) (duda_request_t *, int);
    int (*http_header) (duda_request_t *, char *, int);
    int (*body_print)  (duda_request_t *, char *, int);
    int (*body_printf) (duda_request_t *, const char *, ...);
    int (*sendfile)    (duda_request_t *, char *);
    int (*end) (duda_request_t *, void (*end_callback) ());
};

/* DEBUG object: debug->x() */
struct duda_api_debug {
    /* FIXME: pending interfaces... */
    void (*trace) ();
    void (*stacktrace) (void);
};

/* Global data (thread scope) */
struct duda_api_global {
    int   (*init) (duda_global_t *, void *(*callback)());
    int   (*set)  (duda_global_t, const void *);
    void *(*get)  (duda_global_t);
};

/*
 * Group all objects in one struct so we can pass this memory space
 * to the web service when it's loaded, then the webservice.h macros
 * do the dirty job...
 */
struct duda_api_objects {
    struct duda_api_main *duda;
    struct plugin_api *monkey;
    struct duda_api_map *map;
    struct duda_api_msg *msg;
    struct duda_api_response *response;
    struct duda_api_debug *debug;
    struct duda_api_console *console;
    struct duda_api_global *global;
    struct duda_api_param *param;
    struct duda_api_session *session;
    struct duda_api_cookie *cookie;
    struct duda_api_xtime *xtime;
};

struct duda_api_objects *duda_api_master();

int http_status(duda_request_t *dr, int status);
int http_header(duda_request_t *dr, char *row, int len);
int body_print(duda_request_t *dr, char *raw, int len);
int body_printf(duda_request_t *dr, const char *format, ...);
int sendfile_enqueue(duda_request_t *dr, char *path);
int end_response(duda_request_t *dr, void (*end_cb) (duda_request_t *));

#endif
