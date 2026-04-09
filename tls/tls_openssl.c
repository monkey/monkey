/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>

#include <monkey/monkey.h>
#include <monkey/mk_tls_transport.h>

#ifndef SENDFILE_BUF_SIZE
#define SENDFILE_BUF_SIZE 16384
#endif

/*
 * OPENSSL_VERSION_NUMBER has the following semantics:
 *
 *   0x010100000L   M = major  F = fix    S = status
 *     MMNNFFPPS    N = minor  P = patch
 */
#define OPENSSL_1_1_0 0x010100000L

struct tls_config {
    char *cert_file;
    char *cert_chain_file;
    char *key_file;
    char *dh_param_file;
    int8_t check_client_cert;
};

struct tls_context_head {
    SSL *ssl;
    int fd;
    int want_event;
    struct tls_context_head *_next;
};

struct tls_thread_context {
    struct tls_context_head *contexts;
    struct mk_list _head;
};

struct tls_server_context {
    struct mk_server *server;
    struct tls_config config;
    SSL_CTX *ctx;
    pthread_mutex_t mutex;
    struct mk_list threads;
};

static pthread_key_t local_context;
static int local_context_created = MK_FALSE;
static struct tls_server_context *server_context;

static struct tls_context_head *context_get_head(int fd);

static struct tls_thread_context *local_thread_context(void)
{
    return pthread_getspecific(local_context);
}

static int tls_handle_return(SSL *ssl, int ret)
{
    int error;
    struct tls_context_head *head;

    head = context_get_head(SSL_get_fd(ssl));
    if (head != NULL) {
        head->want_event = MK_EVENT_EMPTY;
    }

    if (ret > 0) {
        return ret;
    }

    error = SSL_get_error(ssl, ret);
    switch (error) {
    case SSL_ERROR_WANT_READ:
        if (head != NULL) {
            head->want_event = MK_EVENT_READ;
        }
        errno = EAGAIN;
        return -1;
    case SSL_ERROR_WANT_WRITE:
        if (head != NULL) {
            head->want_event = MK_EVENT_WRITE;
        }
        errno = EAGAIN;
        return -1;
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    default:
        errno = 0;
        return -1;
    }
}

static int config_parse(const char *confdir, struct tls_config *conf)
{
    long unsigned int len;
    char *conf_path = NULL;
    char *cert_file = NULL;
    char *cert_chain_file = NULL;
    char *key_file = NULL;
    char *dh_param_file = NULL;
    int8_t check_client_cert = MK_FALSE;
    struct mk_rconf_section *section;
    struct mk_rconf *conf_head;

    mk_string_build(&conf_path, &len, "%s/tls.conf", confdir);
    conf_head = mk_rconf_open(conf_path);
    mk_mem_free(conf_path);

    if (conf_head == NULL) {
        goto fallback;
    }

    section = mk_rconf_section_get(conf_head, "TLS");
    if (!section) {
        goto fallback;
    }

    cert_file = mk_rconf_section_get_key(section, "CertificateFile", MK_RCONF_STR);
    cert_chain_file = mk_rconf_section_get_key(section, "CertificateChainFile", MK_RCONF_STR);
    key_file = mk_rconf_section_get_key(section, "RSAKeyFile", MK_RCONF_STR);
    dh_param_file = mk_rconf_section_get_key(section, "DHParameterFile", MK_RCONF_STR);
    check_client_cert = (size_t) mk_rconf_section_get_key(section, "CheckClientCert",
                                                          MK_RCONF_BOOL);

fallback:
    if (!cert_file) {
        mk_string_build(&conf->cert_file, &len, "%s/srv_cert.pem", confdir);
    }
    else if (*cert_file == '/') {
        conf->cert_file = cert_file;
    }
    else {
        mk_string_build(&conf->cert_file, &len, "%s/%s", confdir, cert_file);
        mk_mem_free(cert_file);
    }

    if (cert_chain_file == NULL) {
        conf->cert_chain_file = NULL;
    }
    else if (*cert_chain_file == '/') {
        conf->cert_chain_file = cert_chain_file;
    }
    else {
        mk_string_build(&conf->cert_chain_file, &len, "%s/%s", confdir, cert_chain_file);
        mk_mem_free(cert_chain_file);
    }

    if (!key_file) {
        mk_string_build(&conf->key_file, &len, "%s/rsa.pem", confdir);
    }
    else if (*key_file == '/') {
        conf->key_file = key_file;
    }
    else {
        mk_string_build(&conf->key_file, &len, "%s/%s", confdir, key_file);
        mk_mem_free(key_file);
    }

    if (!dh_param_file) {
        mk_string_build(&conf->dh_param_file, &len, "%s/dhparam.pem", confdir);
    }
    else if (*dh_param_file == '/') {
        conf->dh_param_file = dh_param_file;
    }
    else {
        mk_string_build(&conf->dh_param_file, &len, "%s/%s", confdir, dh_param_file);
        mk_mem_free(dh_param_file);
    }

    conf->check_client_cert = check_client_cert;

    if (conf_head) {
        mk_rconf_free(conf_head);
    }

    return 0;
}

static void config_free(struct tls_config *conf)
{
    if (conf->cert_file) mk_mem_free(conf->cert_file);
    if (conf->cert_chain_file) mk_mem_free(conf->cert_chain_file);
    if (conf->key_file) mk_mem_free(conf->key_file);
    if (conf->dh_param_file) mk_mem_free(conf->dh_param_file);
}

static void tls_init_library(void)
{
#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
    OPENSSL_add_all_algorithms_noconf();
    SSL_load_error_strings();
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();
#endif
}

static SSL_CTX *tls_create_server_context(void)
{
#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
    return SSL_CTX_new(SSLv23_server_method());
#else
    return SSL_CTX_new(TLS_server_method());
#endif
}

static int tls_configure_dh(struct tls_server_context *ctx)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    BIO *bio;
    DH *dh;

    bio = BIO_new_file(ctx->config.dh_param_file, "r");
    if (bio == NULL) {
        return 0;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (dh == NULL) {
        return 0;
    }

    if (SSL_CTX_set_tmp_dh(ctx->ctx, dh) != 1) {
        DH_free(dh);
        return -1;
    }

    DH_free(dh);
    return 0;
#else
#ifdef SSL_CTX_set_dh_auto
    if (SSL_CTX_set_dh_auto(ctx->ctx, 1) != 1) {
        return -1;
    }
#endif
    return 0;
#endif
}

static int tls_load_credentials(struct tls_server_context *ctx)
{
    if (SSL_CTX_use_certificate_chain_file(ctx->ctx, ctx->config.cert_file) != 1) {
        mk_warn("[tls] failed to load certificate chain from %s",
                ctx->config.cert_file);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ctx, ctx->config.key_file,
                                    SSL_FILETYPE_PEM) != 1) {
        mk_warn("[tls] failed to load private key from %s",
                ctx->config.key_file);
        return -1;
    }

    if (SSL_CTX_check_private_key(ctx->ctx) != 1) {
        mk_warn("[tls] certificate/private key mismatch");
        return -1;
    }

    if (ctx->config.cert_chain_file != NULL) {
        if (SSL_CTX_load_verify_locations(ctx->ctx,
                                          ctx->config.cert_chain_file,
                                          NULL) != 1) {
            mk_warn("[tls] failed to load CA chain from %s",
                    ctx->config.cert_chain_file);
            return -1;
        }
    }

    if (tls_configure_dh(ctx) != 0) {
        mk_warn("[tls] failed to configure DH parameters");
        return -1;
    }

    return 0;
}

static struct tls_context_head *context_get_head(int fd)
{
    struct tls_thread_context *thctx;
    struct tls_context_head *cur;

    thctx = local_thread_context();
    if (thctx == NULL) {
        return NULL;
    }

    cur = thctx->contexts;
    while (cur) {
        if (cur->fd == fd) {
            return cur;
        }
        cur = cur->_next;
    }

    return NULL;
}

static SSL *context_get(int fd)
{
    struct tls_context_head *head;

    head = context_get_head(fd);
    if (head == NULL) {
        return NULL;
    }

    return head->ssl;
}

static SSL *context_new(int fd)
{
    SSL *ssl;
    struct tls_context_head *ctx_head;
    struct tls_thread_context *thctx;

    thctx = local_thread_context();
    if (thctx == NULL) {
        return NULL;
    }

    ctx_head = context_get_head(-1);
    if (ctx_head == NULL) {
        ctx_head = mk_mem_alloc_z(sizeof(struct tls_context_head));
        if (ctx_head == NULL) {
            return NULL;
        }
        ctx_head->fd = -1;
        ctx_head->want_event = MK_EVENT_READ;
        ctx_head->_next = thctx->contexts;
        thctx->contexts = ctx_head;
    }

    ssl = SSL_new(server_context->ctx);
    if (ssl == NULL) {
        return NULL;
    }

    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    ctx_head->ssl = ssl;
    ctx_head->fd = fd;

    return ssl;
}

static void context_unset(int fd)
{
    struct tls_context_head *ctx_head;

    ctx_head = context_get_head(fd);
    if (ctx_head == NULL) {
        return;
    }

    if (ctx_head->ssl != NULL) {
        SSL_shutdown(ctx_head->ssl);
        SSL_free(ctx_head->ssl);
        ctx_head->ssl = NULL;
    }
    ctx_head->fd = -1;
}

static void contexts_free(struct tls_context_head *ctx)
{
    struct tls_context_head *cur;
    struct tls_context_head *tmp;

    cur = ctx;
    while (cur) {
        tmp = cur->_next;
        if (cur->ssl != NULL) {
            SSL_free(cur->ssl);
        }
        mk_mem_free(cur);
        cur = tmp;
    }
}

static SSL *context_get_or_create(int fd)
{
    SSL *ssl;

    ssl = context_get(fd);
    if (ssl != NULL) {
        return ssl;
    }

    return context_new(fd);
}

static int mk_tls_read(struct mk_plugin *plugin, int fd, void *buf, int count)
{
    SSL *ssl;

    (void) plugin;

    ssl = context_get_or_create(fd);
    if (ssl == NULL) {
        return -1;
    }

    return tls_handle_return(ssl, SSL_read(ssl, buf, count));
}

static int mk_tls_write(struct mk_plugin *plugin, int fd,
                        const void *buf, size_t count)
{
    SSL *ssl;

    (void) plugin;

    ssl = context_get_or_create(fd);
    if (ssl == NULL) {
        return -1;
    }

    return tls_handle_return(ssl, SSL_write(ssl, buf, count));
}

static int mk_tls_writev(struct mk_plugin *plugin, int fd, struct mk_iov *mk_io)
{
    int i;
    int ret;
    SSL *ssl;
    size_t used;
    size_t len;
    unsigned char *buf;

    (void) plugin;

    ssl = context_get_or_create(fd);
    if (ssl == NULL) {
        return -1;
    }

    len = mk_io->total_len;
    buf = mk_mem_alloc(len);
    if (buf == NULL) {
        return -1;
    }

    used = 0;
    for (i = 0; i < mk_io->iov_idx; i++) {
        memcpy(buf + used, mk_io->io[i].iov_base, mk_io->io[i].iov_len);
        used += mk_io->io[i].iov_len;
    }

    ret = SSL_write(ssl, buf, len);
    mk_mem_free(buf);

    return tls_handle_return(ssl, ret);
}

static int mk_tls_send_file(struct mk_plugin *plugin, int fd, int file_fd,
                            off_t *file_offset, size_t file_count)
{
    int ret;
    SSL *ssl;
    ssize_t used;
    ssize_t remain;
    ssize_t sent;
    unsigned char *buf;

    (void) plugin;

    ssl = context_get_or_create(fd);
    if (ssl == NULL) {
        return -1;
    }

    buf = mk_mem_alloc(SENDFILE_BUF_SIZE);
    if (buf == NULL) {
        return -1;
    }

    sent = 0;
    remain = file_count;

    do {
        used = pread(file_fd, buf, SENDFILE_BUF_SIZE, *file_offset);
        if (used == 0) {
            ret = 0;
        }
        else if (used < 0) {
            ret = -1;
        }
        else if (remain > 0) {
            ret = SSL_write(ssl, buf, used < remain ? used : remain);
        }
        else {
            ret = SSL_write(ssl, buf, used);
        }

        if (ret > 0) {
            if (remain > 0) {
                remain -= ret;
            }
            sent += ret;
            *file_offset += ret;
        }
    } while (ret > 0);

    mk_mem_free(buf);

    if (sent > 0) {
        return sent;
    }

    return tls_handle_return(ssl, ret);
}

static int mk_tls_close(struct mk_plugin *plugin, int fd)
{
    (void) plugin;

    context_unset(fd);
    close(fd);
    return 0;
}

static int tls_event_interest(struct mk_plugin *plugin, int fd, int fallback)
{
    struct tls_context_head *ctx_head;

    (void) plugin;

    ctx_head = context_get_head(fd);
    if (ctx_head == NULL) {
        return fallback;
    }

    if (ctx_head->want_event == MK_EVENT_EMPTY) {
        return fallback;
    }

    return ctx_head->want_event;
}

int mk_tls_enabled(void)
{
    return MK_TRUE;
}

int mk_tls_init(struct mk_server *server)
{
    int used;
    struct mk_list *head;
    struct mk_config_listener *listen;

    used = MK_FALSE;
    mk_list_foreach(head, &server->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);
        if (listen->flags & MK_CAP_SOCK_TLS) {
            used = MK_TRUE;
            break;
        }
    }

    if (!used) {
        return 0;
    }

    server_context = mk_mem_alloc_z(sizeof(struct tls_server_context));
    if (server_context == NULL) {
        return -1;
    }

    server_context->server = server;
    config_parse(server->path_conf_root, &server_context->config);
    pthread_mutex_init(&server_context->mutex, NULL);
    mk_list_init(&server_context->threads);
    if (local_context_created == MK_FALSE) {
        pthread_key_create(&local_context, NULL);
        local_context_created = MK_TRUE;
    }

    tls_init_library();

    server_context->ctx = tls_create_server_context();
    if (server_context->ctx == NULL) {
        return -1;
    }

#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(server_context->ctx, 1);
#endif
#endif

    SSL_CTX_set_mode(server_context->ctx,
                     SSL_MODE_ENABLE_PARTIAL_WRITE |
                     SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(server_context->ctx, SSL_SESS_CACHE_SERVER);

    if (server_context->config.check_client_cert == MK_TRUE) {
        SSL_CTX_set_verify(server_context->ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           NULL);
    }
    else {
        SSL_CTX_set_verify(server_context->ctx, SSL_VERIFY_NONE, NULL);
    }

    return tls_load_credentials(server_context);
}

void mk_tls_thread_init(struct mk_server *server)
{
    struct tls_thread_context *thctx;

    (void) server;

    if (server_context == NULL) {
        return;
    }

    thctx = mk_mem_alloc_z(sizeof(struct tls_thread_context));
    if (thctx == NULL) {
        exit(EXIT_FAILURE);
    }

    pthread_mutex_lock(&server_context->mutex);
    mk_list_add(&thctx->_head, &server_context->threads);
    pthread_mutex_unlock(&server_context->mutex);

    pthread_setspecific(local_context, thctx);
}

void mk_tls_exit(struct mk_server *server)
{
    struct mk_list *cur;
    struct mk_list *tmp;
    struct tls_thread_context *thctx;
    (void) server;

    if (server_context == NULL) {
        return;
    }

    mk_list_foreach_safe(cur, tmp, &server_context->threads) {
        thctx = mk_list_entry(cur, struct tls_thread_context, _head);
        contexts_free(thctx->contexts);
        mk_mem_free(thctx);
    }

    if (server_context->ctx != NULL) {
        SSL_CTX_free(server_context->ctx);
    }

    config_free(&server_context->config);
    pthread_mutex_destroy(&server_context->mutex);
    mk_mem_free(server_context);
    server_context = NULL;

    if (local_context_created == MK_TRUE) {
        pthread_key_delete(local_context);
        local_context_created = MK_FALSE;
    }
}

static struct mk_plugin_network mk_tls_io = {
    .read        = mk_tls_read,
    .write       = mk_tls_write,
    .writev      = mk_tls_writev,
    .close       = mk_tls_close,
    .send_file   = mk_tls_send_file,
    .event_interest = tls_event_interest,
    .buffer_size = 16384
};

struct mk_plugin_network *mk_tls_transport(void)
{
    return &mk_tls_io;
}
