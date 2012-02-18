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
}

void *callback_cpu_hz()
{
    mk_info("callback cpu_hz()");
}

void *callback_cpu_list()
{
    mk_info("callback cpu_list()");
}

int duda_map()
{
    duda_interface_t *if_system;
    duda_method_t    *method;
    duda_param_t     *param;

    duda_map_init();

    /* archive interface */
    if_system = duda_interface_new("system");

    /* /app/archive/list */
    method = duda_method_new("cpu_usage", (void *) callback_cpu_usage, 1);
    method_add_param(method, "cpu_id", 5);
    interface_add_method(method, if_system);

    method = duda_method_new("cpu_hz", (void *) callback_cpu_hz, 1);
    method_add_param(method, "cpu_id", 5);
    interface_add_method(method, if_system);

    method = duda_method_new("cpu_list", (void *) callback_cpu_list, 0);
    interface_add_method(method, if_system);

    /* Add interface to map */
    duda_map_add_interface(if_system);

    duda_map_end();
}
