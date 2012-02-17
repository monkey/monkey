/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "MKPlugin.h"
#include "webservice.h"

/* Creates a new interface */
duda_interface_t *duda_interface_new(const char *uid)
{
  duda_interface_t *iface;
  
  iface = mk_api->mem_alloc(sizeof(duda_interface_t));
  iface->uid = uid;
  mk_list_init(&iface->methods);

  return iface;
}

/* Add a method to an interface */
void duda_interface_add_method(duda_interface_t *iface,
                               struct mk_list *iface_list)
{
    mk_list_add(&iface->_head, iface_list);
}


/* Creates a new method */
duda_method_t *duda_method_new(const char *uid, void (*callback) (void *), int n_params)
{
    duda_method_t *method;
    
    method = mk_api->mem_alloc(sizeof(duda_method_t));
    method->uid = uid;
    method->num_params = n_params;
    mk_list_init(&method->params);
    
    return method;
}

/* Add a parameter to a method */
void duda_method_add_param(duda_param_t *param, duda_method_t *method)
{
    mk_list_add(&param->_head, &method->_head);
}

/* Creates a new parameter */
duda_param_t *duda_param_new(const char *uid, short int max_len)
{
    duda_param_t *param;

    param = mk_api->mem_alloc(sizeof(duda_method_t));
    param->max_len = max_len;

    return param;
}
