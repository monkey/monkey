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

void cb_cpu_usage(duda_request_t *dr)
{
    response->http_status(dr, 200);
    response->http_header(dr, "Content-Type: text/plain", 24);
    //response->body_write(dr, "hello world\n", 12);

    char *buf = monkey->file_to_buffer("/home/edsiper/kernel_sdhc_log_001.txt");
    response->body_write(dr, buf, strlen(buf));

    response->end(dr);
}

void cb_cpu_hz(duda_request_t *dr)
{
    msg->info("callback cpu_hz()");
}

void cb_cpu_list(duda_request_t *dr)
{
    msg->info("callback cpu_list()");
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
    method = map->method_new("cpu_usage", "cb_cpu_usage", 1);
    param = map->param_new("cpu_id", 5);
    map->method_add_param(param, method);
    map->interface_add_method(method, if_system);

    method = map->method_new("cpu_hz", "cb_cpu_hz", 1);
    param = map->param_new("cpu_id", 5);
    map->method_add_param(param, method);
    map->interface_add_method(method, if_system);

    method = map->method_new("cpu_list", "cb_cpu_list", 0);
    map->interface_add_method(method, if_system);

    /* Add interface to map */
    duda_service_add_interface(if_system);

    duda_service_ready();
}
