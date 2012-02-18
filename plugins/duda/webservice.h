/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef DUDA_WEBSERVICE_H
#define DUDA_WEBSERVICE_H

#include "mk_list.h"

/* The basic web service information */
struct duda_webservice {
    const char *app_name;
    const char *app_path;
};

/* Interfaces of the web service */
struct duda_interface {
    const char *uid;
    struct mk_list methods;

    /* mk_list */
    struct mk_list _head;
};

/* Methods associated to an interface */
struct duda_method {
    const char *uid;
    short int num_params;
    void *(*callback);

    struct mk_list params;

    /* mk_list */
    struct mk_list _head;
};

/* Parameters: each method supports N parameters */
struct duda_param {
    const char *name;
    short int max_len;

    /* mk_list */
    struct mk_list _head;
};

/* types of data */
typedef struct duda_interface duda_interface_t;
typedef struct duda_method duda_method_t;
typedef struct duda_param duda_param_t;
typedef void * duda_callback_t;

struct duda_webservice ws;
struct mk_list _duda_interfaces;

struct duda_api *duda;

/* Duda Macros */
#define DUDA_REGISTER(app_name, app_path) struct duda_webservice ws = {app_name, app_path}
#define duda_service_init() do {                 \
        mk_list_init(&_duda_interfaces);         \
        duda = api;                              \
    } while(0);

#define duda_service_add_interface(iface) do {              \
        mk_list_add(&iface->_head, &_duda_interfaces);      \
    } while(0);

#define duda_service_ready() do {               \
        PLUGIN_TRACE("service ready");          \
        return 0;                               \
    } while(0);

#define duda_map_add_interface(iface) mk_list_add(&iface->_head, &_duda_interfaces)

/* API functions */
duda_interface_t *duda_interface_new(const char *uid);
duda_method_t *duda_method_new(const char *uid, void (*callback) (void *), int n_params);
duda_param_t *duda_param_new(const char *uid, short int max_len);

void duda_interface_add_method(duda_method_t *method, duda_interface_t *iface);
void duda_method_add_param(duda_param_t *param, duda_method_t *method);

struct duda_api *duda_api_to_object();

/* API object */
struct duda_api {
    /* interface_ */
    duda_interface_t *(*interface_new) (const char *);
    void (*interface_add_method) (duda_method_t *, duda_interface_t *);

    /* method_ */
    duda_method_t *(*method_new) (const char *, void (*) (void *), int);
    void (*method_add_param) (duda_param_t *, duda_method_t *);

    /* param_ */
    duda_param_t *(*param_new) (const char *, short int);
};

#endif
