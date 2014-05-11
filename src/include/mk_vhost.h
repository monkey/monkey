/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mk_list.h"
#include "mk_config.h"
#include "mk_request.h"

#ifndef MK_VHOST_H
#define MK_VHOST_H

/* Custom error page */
struct error_page {
    short int status;
    char *file;
    char *real_path;
    struct mk_list _head;
};

struct host
{
    char *file;                   /* configuration file */
    struct mk_list server_names;  /* host names (a b c...) */

    mk_ptr_t documentroot;

    char *host_signature;
    mk_ptr_t header_host_signature;

    /* source configuration */
    struct mk_config *config;

    /* custom error pages */
    struct mk_list error_pages;

    /* link node */
    struct mk_list _head;
};

struct host_alias
{
    char *name;
    unsigned int len;

    struct mk_list _head;
};


#define VHOST_FDT_HASHTABLE_SIZE   64
#define VHOST_FDT_HASHTABLE_CHAINS  8

struct vhost_fdt_hash_chain {
    int fd;
    int readers;
    unsigned int hash;
};

struct vhost_fdt_hash_table {
    int av_slots;
    struct vhost_fdt_hash_chain chain[VHOST_FDT_HASHTABLE_CHAINS];
};

struct vhost_fdt_host {
    struct host *host;
    struct vhost_fdt_hash_table hash_table[VHOST_FDT_HASHTABLE_SIZE];
    struct mk_list _head;
};

//pthread_key_t mk_vhost_fdt_key;
pthread_mutex_t mk_vhost_fdt_mutex;

struct host *mk_vhost_read(char *path);
int mk_vhost_get(mk_ptr_t host, struct host **vhost, struct host_alias **alias);
void mk_vhost_init(char *path);
int mk_vhost_fdt_worker_init();
int mk_vhost_open(struct session_request *sr);
int mk_vhost_close(struct session_request *sr);

#ifdef SAFE_FREE
void mk_vhost_free_all();
#endif

#endif
