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
    msg->info("callback cpu_usage()");
    return NULL;
}

void *callback_cpu_hz()
{
    msg->info("callback cpu_hz()");
    return NULL;
}

void *callback_cpu_list()
{
    msg->info("callback cpu_list()");
    return NULL;
}

int duda_init(struct duda_api_objects *api)
{
    duda_interface_t *if_system;
    duda_method_t    *method;
    duda_param_t     *param;

    duda_service_init();

    /* archive interface */
    if_system = map->interface_new("system");

    /* /app/archive/list */
    method = map->method_new("cpu_usage", "callback_cpu_usage", 1);
    param = map->param_new("cpu_id", 5);
    map->method_add_param(param, method);
    map->interface_add_method(method, if_system);

    method = map->method_new("cpu_hz", "callback_cpu_hz", 1);
    param = map->param_new("cpu_id", 5);
    map->method_add_param(param, method);
    map->interface_add_method(method, if_system);

    method = map->method_new("cpu_list", "callback_cpu_list", 0);
    map->interface_add_method(method, if_system);

    /* Add interface to map */
    duda_service_add_interface(if_system);

    struct mk_list *head;
    struct duda_interface *entry;

    mk_list_foreach(head, &_duda_interfaces) {
        entry = mk_list_entry(head, struct duda_interface, _head);
        msg->info("interface: %s", entry->uid);
   }



    duda_service_ready();
}
