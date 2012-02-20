/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "webservice.h"

DUDA_REGISTER("Service Example", "service");

/*
 *
 * URI Map example
 * +--------------------------------------------------------------+
 * |  Interface         Method     Param Name  Param Max Length   |
 * +--------------------------------------------------------------+
 * |  system           cpu_usage     cpu_id          5            |
 * +--------------------------------------------------------------+
 * |                   cpu_hz        cpu_id          5            |
 * +--------------------------------------------------------------+
 * |                   cpu_list                                   |                 
 * +--------------------------------------------------------------+
 *
 */

void *callback_cpu_usage()
{
    mk_info("callback cpu_usage()");
    return NULL;
}

void *callback_cpu_hz()
{
    mk_info("callback cpu_hz()");
    return NULL;
}

void *callback_cpu_list()
{
    mk_info("callback cpu_list()");
    return NULL;
}

int duda_init(struct duda_api *api)
{
    duda_interface_t *if_system;
    duda_method_t    *method;
    duda_param_t     *param;

    //duda_service_init();
    duda = api;
    _duda_interfaces = malloc(sizeof(struct mk_list));
    mk_info("->%p", _duda_interfaces);
    mk_list_init(_duda_interfaces);
    mk_info("->%p", _duda_interfaces);

    /* archive interface */
    if_system = duda->interface_new("system");

    /* /app/archive/list */
    method = duda->method_new("cpu_usage", (void *) callback_cpu_usage, 1);
    param = duda->param_new("cpu_id", 5);
    duda->method_add_param(param, method);
    duda->interface_add_method(method, if_system);

    method = duda->method_new("cpu_hz", (void *) callback_cpu_hz, 1);
    param = duda->param_new("cpu_id", 5);
    duda->method_add_param(param, method);
    duda->interface_add_method(method, if_system);

    method = duda->method_new("cpu_list", (void *) callback_cpu_list, 0);
    duda->interface_add_method(method, if_system);

    /* Add interface to map */
    duda_service_add_interface(if_system);

    struct mk_list *head;
    struct duda_interface *entry;
    
    mk_list_foreach(head, _duda_interfaces) {
        entry = mk_list_entry(head, struct duda_interface, _head);
        mk_warn("%s", entry->uid);
   }



    duda_service_ready();
}
