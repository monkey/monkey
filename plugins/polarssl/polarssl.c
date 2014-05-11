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

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#include <polarssl/version.h>
#include <polarssl/error.h>
#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/bignum.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>

#if (POLARSSL_VERSION_NUMBER >= 0x01020000)
#include <polarssl/ssl_cache.h>
#endif // POLARSSL_VERSION_NUMBER

#if (POLARSSL_VERSION_NUMBER >= 0x01030000)
#include <polarssl/pk.h>
#endif

#include "MKPlugin.h"

#ifndef SENDFILE_BUF_SIZE
#define SENDFILE_BUF_SIZE SSL_MAX_CONTENT_LEN
#endif

#ifndef POLAR_DEBUG_LEVEL
#define POLAR_DEBUG_LEVEL 0
#endif

#if (POLARSSL_VERSION_NUMBER < 0x01010000)
#error "Require polarssl 1.1 or higher."
#endif

#if (!defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_ENTROPY_C) || \
        !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_SRV_C) || \
        !defined(POLARSSL_NET_C) || !defined(POLARSSL_RSA_C) || \
        !defined(POLARSSL_CTR_DRBG_C))
#error "One or more required POLARSSL modules not built."
#endif

MONKEY_PLUGIN("polarssl",         /* shortname */
        "PolarSSL transport plugin", /* name */
        "0.1",        /* version */
        MK_PLUGIN_CORE_THCTX | MK_PLUGIN_NETWORK_IO);

struct polar_config {
    char *cert_file;
    char *cert_chain_file;
    char *key_file;
    char *dh_param_file;
};

#if defined(POLARSSL_SSL_CACHE_C)
struct polar_sessions {
    pthread_mutex_t _mutex;
    ssl_cache_context cache;
};

static struct polar_sessions global_sessions = {
    ._mutex = PTHREAD_MUTEX_INITIALIZER,
};

#endif

struct polar_context_head {
    ssl_context context;
    int fd;
    struct polar_context_head *_next;
};

struct polar_thread_context {

    struct polar_context_head *contexts;

    ctr_drbg_context ctr_drbg;
#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    rsa_context rsa;
#else
    pk_context pkey;
#endif

    struct mk_list _head;
};

struct polar_server_context {

    struct polar_config config;

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    x509_cert cert;
    x509_cert ca_cert;
#else
    x509_crt cert;
    x509_crt ca_cert;
#endif

    pthread_mutex_t _mutex;
    dhm_context dhm;
    entropy_context entropy;

    struct polar_thread_context threads;
};

static struct polar_server_context server_context = {
    ._mutex = PTHREAD_MUTEX_INITIALIZER,
};

static const char *my_dhm_P = POLARSSL_DHM_RFC5114_MODP_1024_P;
static const char *my_dhm_G = POLARSSL_DHM_RFC5114_MODP_1024_G;

static pthread_key_t local_context;

static struct polar_thread_context *local_thread_context(void)
{
    return pthread_getspecific(local_context);
}

static int entropy_func_safe(void *data, unsigned char *output, size_t len)
{
    int ret;

    pthread_mutex_lock(&server_context._mutex);
    ret = entropy_func(data, output, len);
    pthread_mutex_unlock(&server_context._mutex);

    return ret;
}

#if (POLAR_DEBUG_LEVEL > 0)
static void polar_debug(void *ctx, int level, const char *str)
{
    (void)ctx;

    if (level < POLAR_DEBUG_LEVEL) {
        mk_warn("%.*s", (int)strlen(str) - 1, str);
    }
}
#endif

static int handle_return(int ret)
{
#if defined(TRACE)
    char err_buf[72];
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));
        PLUGIN_TRACE("[polarssl] SSL error: %s", err_buf);
    }
#endif
    if (ret < 0) {
        switch( ret )
        {
            case POLARSSL_ERR_NET_WANT_READ:
            case POLARSSL_ERR_NET_WANT_WRITE:
                if (errno != EAGAIN)
                    errno = EAGAIN;
		return -1;
            case POLARSSL_ERR_SSL_CONN_EOF:
                return 0;
            default:
                if (errno == EAGAIN)
		    errno = 0;
                return -1;
        }
    }
    else {
        return ret;
    }
}

static int config_parse(const char *confdir, struct polar_config *conf)
{
    long unsigned int len;
    char *conf_path = NULL;
    struct mk_config_section *section;
    struct mk_config *conf_head;
    struct mk_list *head;

    mk_api->str_build(&conf_path, &len, "%spolarssl.conf", confdir);
    conf_head = mk_api->config_create(conf_path);
    mk_api->mem_free(conf_path);

    if (conf_head == NULL) {
        goto fallback;
    }

    mk_list_foreach(head, &conf_head->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);

        if (strcasecmp(section->name, "SSL")) {
            continue;
        }
        conf->cert_file = mk_api->config_section_getval(section,
                "CertificateFile",
                MK_CONFIG_VAL_STR);
        conf->cert_chain_file = mk_api->config_section_getval(section,
                "CertificateChainFile",
                MK_CONFIG_VAL_STR);
        conf->key_file = mk_api->config_section_getval(section,
                "RSAKeyFile",
                MK_CONFIG_VAL_STR);
        conf->dh_param_file = mk_api->config_section_getval(section,
                "DHParameterFile",
                MK_CONFIG_VAL_STR);
    }
    mk_api->config_free(conf_head);

fallback:
    if (conf->cert_file == NULL) {
        mk_api->str_build(&conf->cert_file, &len,
                "%ssrv_cert.pem", confdir);
    }
    if (conf->key_file == NULL) {
        mk_api->str_build(&conf->key_file, &len,
                "%srsa.pem", confdir);
    }
    if (conf->dh_param_file == NULL) {
        mk_api->str_build(&conf->dh_param_file, &len,
                "%sdhparam.pem", confdir);
    }
    return 0;
}

static int polar_load_certs(const struct polar_config *conf)
{
    char err_buf[72];
    int ret;

    assert(conf->cert_file != NULL);

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    ret = x509parse_crtfile(&server_context.cert, conf->cert_file);
#else
    ret = x509_crt_parse_file(&server_context.cert, conf->cert_file);
#endif
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));
        mk_err("[polarssl] Load cert '%s' failed: %s",
                conf->cert_file,
                err_buf);

#if defined(POLARSSL_CERTS_C)
        mk_warn("[polarssl] Using test certificates, "
                "please set 'CertificateFile' in polarssl.conf");

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
        ret = x509parse_crt(&server_context.cert,
                (unsigned char *)test_srv_crt, strlen(test_srv_crt));
#else
        ret = x509_crt_parse(&server_context.cert,
                (unsigned char *)test_srv_crt, strlen(test_srv_crt));
#endif
        if (ret) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_err("[polarssl] Load built-in cert failed: %s", err_buf);
            return -1;
        }
#else
        return -1;
#endif // defined(POLARSSL_CERTS_C)
    }
    else if (conf->cert_chain_file != NULL) {
#if (POLARSSL_VERSION_NUMBER < 0x01030000)
        ret = x509parse_crtfile(server_context.ca_cert.next,
		conf->cert_chain_file);
#else
	ret = x509_crt_parse_file(server_context.ca_cert.next,
		conf->cert_chain_file);
#endif
        if (ret) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_warn("[polarssl] Load cert chain '%s' failed: %s",
                    conf->cert_chain_file,
                    err_buf);
        }
    }

    return 0;
}

static int polar_load_key(struct polar_thread_context *thread_context,
		const struct polar_config *conf)
{
    char err_buf[72];
    int ret;

    assert(conf->key_file);

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    ret = x509parse_keyfile(&thread_context->rsa, conf->key_file, NULL);
#else
    ret = pk_parse_keyfile(&thread_context->pkey, conf->key_file, NULL);
#endif
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));
        MK_TRACE("[polarssl] Load key '%s' failed: %s",
                conf->key_file,
                err_buf);

#if defined(POLARSSL_CERTS_C)

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
        ret = x509parse_key(&thread_context->rsa,
                (unsigned char *)test_srv_key, strlen(test_srv_key), NULL, 0);
#else
	ret = pk_parse_key(&thread_context->pkey,
		(unsigned char *)test_srv_key, strlen(test_srv_key), NULL, 0);
#endif
        if (ret) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_err("[polarssl] Failed to load built-in RSA key: %s", err_buf);
            return -1;
        }
#else
        return -1;
#endif // defined(POLARSSL_CERTS_C)
    }
    return 0;
}

static int polar_load_dh_param(const struct polar_config *conf)
{
    char err_buf[72];
    int ret;

    assert(conf->dh_param_file);

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    ret = x509parse_dhmfile(&server_context.dhm, conf->dh_param_file);
#else
    ret = dhm_parse_dhmfile(&server_context.dhm, conf->dh_param_file);
#endif
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));

        ret = mpi_read_string(&server_context.dhm.P, 16, my_dhm_P);
        if (ret < 0) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_err("[polarssl] Load DH parameter failed: %s", err_buf);
            return -1;
        }
        ret = mpi_read_string(&server_context.dhm.G, 16, my_dhm_G);
        if (ret < 0) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_err("[polarssl] Load DH parameter failed: %s", err_buf);
            return -1;
        }
    }

    return 0;
}

static int polar_init(void)
{
    pthread_key_create(&local_context, NULL);

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init(&global_sessions.cache);
#endif

    pthread_mutex_lock(&server_context._mutex);
    mk_list_init(&server_context.threads._head);

    memset(&server_context.cert, 0, sizeof(server_context.cert));
    memset(&server_context.ca_cert, 0, sizeof(server_context.ca_cert));
    memset(&server_context.dhm, 0, sizeof(server_context.dhm));
    entropy_init(&server_context.entropy);

    pthread_mutex_unlock(&server_context._mutex);

    PLUGIN_TRACE("[polarssl] Load certificates.");
    if (polar_load_certs(&server_context.config)) {
        return -1;
    }
    PLUGIN_TRACE("[polarssl] Load DH parameters.");
    if (polar_load_dh_param(&server_context.config)) {
        return -1;
    }

    return 0;
}

static int polar_thread_init(const struct polar_config *conf)
{
    struct polar_thread_context *thctx;
    int ret;

    PLUGIN_TRACE("[polarssl] Init thread context.");

    thctx = mk_api->mem_alloc(sizeof(*thctx));
    if (thctx == NULL) {
        return -1;
    }
    thctx->contexts = NULL;
    mk_list_init(&thctx->_head);

    pthread_mutex_lock(&server_context._mutex);
    mk_list_add(&thctx->_head, &server_context.threads._head);
    pthread_mutex_unlock(&server_context._mutex);

    ret = ctr_drbg_init(&thctx->ctr_drbg,
            entropy_func_safe, &server_context.entropy,
            NULL, 0);
    if (ret) {
        mk_err("crt_drbg_init failed: %d", ret);
        mk_api->mem_free(thctx);
        return -1;
    }

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    rsa_init(&thctx->rsa, RSA_PKCS_V15, 0);
#else
    pk_init(&thctx->pkey);
#endif

    PLUGIN_TRACE("[polarssl] Load RSA key.");
    if (polar_load_key(thctx, conf)) {
        return -1;
    }

    PLUGIN_TRACE("[polarssl] Set local thread context.");
    pthread_setspecific(local_context, thctx);

    return 0;
}

static void contexts_free(struct polar_context_head *ctx)
{
    struct polar_context_head *cur, *next;

    if (ctx != NULL) {
        cur  = ctx;
        next = cur->_next;

        for (; next; cur = next, next = next->_next) {
            ssl_free(&cur->context);
            memset(cur, 0, sizeof(*cur));
            mk_api->mem_free(cur);
        }

        ssl_free(&cur->context);
        memset(cur, 0, sizeof(*cur));
        mk_api->mem_free(cur);
    }
}

static void config_free(struct polar_config *conf)
{
    if (conf->cert_file) mk_api->mem_free(conf->cert_file);
    if (conf->cert_chain_file) mk_api->mem_free(conf->cert_chain_file);
    if (conf->key_file) mk_api->mem_free(conf->key_file);
    if (conf->dh_param_file) mk_api->mem_free(conf->dh_param_file);
}

static void polar_exit(void)
{
    struct mk_list *cur, *tmp;
    struct polar_thread_context *thctx;

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
    x509_free(&server_context.cert);
    x509_free(&server_context.ca_cert);
#else
    x509_crt_free(&server_context.cert);
    x509_crt_free(&server_context.ca_cert);
#endif
    dhm_free(&server_context.dhm);

    mk_list_foreach_safe(cur, tmp, &server_context.threads._head) {
        thctx = mk_list_entry(cur, struct polar_thread_context, _head);
        contexts_free(thctx->contexts);
        mk_api->mem_free(thctx);

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
	rsa_free(&thctx->rsa);
#else
	pk_free(&thctx->pkey);
#endif
    }
    pthread_mutex_destroy(&server_context._mutex);

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free(&global_sessions.cache);
#endif

    config_free(&server_context.config);
}

/* Contexts may be requested from outside workers on exit so we should
 * be prepared for an empty context.
 */
static ssl_context *context_get(int fd)
{
    struct polar_thread_context *thctx = local_thread_context();
    struct polar_context_head **cur = &thctx->contexts;

    if (cur == NULL) {
        return NULL;
    }

    for (; *cur; cur = &(*cur)->_next) {
        if ((*cur)->fd == fd) {
            return &(*cur)->context;
        }
    }

    return NULL;
}

static int polar_cache_get(void *p, ssl_session *session)
{
    struct polar_sessions *session_cache;
    int ret;

    session_cache = p;
    pthread_mutex_lock(&session_cache->_mutex);
    ret = ssl_cache_get(&session_cache->cache, session);
    pthread_mutex_unlock(&session_cache->_mutex);

    return ret;
}

static int polar_cache_set(void *p, const ssl_session *session)
{
    struct polar_sessions *session_cache;
    int ret;

    session_cache = p;
    pthread_mutex_lock(&session_cache->_mutex);
    ret = ssl_cache_set(&session_cache->cache, session);
    pthread_mutex_unlock(&session_cache->_mutex);

    return ret;
}

static ssl_context *context_new(int fd)
{
    struct polar_thread_context *thctx = local_thread_context();
    struct polar_context_head **cur = &thctx->contexts;
    ssl_context *ssl = NULL;

    assert(cur != NULL);

    for (; *cur; cur = &(*cur)->_next) {
        if ((*cur)->fd == -1) {
            break;
        }
    }

    if (*cur == NULL) {
        PLUGIN_TRACE("[polarssl %d] New ssl context.", fd);

        *cur = mk_api->mem_alloc(sizeof(**cur));
        if (*cur == NULL) {
            return NULL;
        }
        (*cur)->_next = NULL;

        ssl = &(*cur)->context;

        ssl_init(ssl);
        ssl_set_endpoint(ssl, SSL_IS_SERVER);
        ssl_set_authmode(ssl, SSL_VERIFY_NONE);

        ssl_set_rng(ssl, ctr_drbg_random, &thctx->ctr_drbg);

#if (POLAR_DEBUG_LEVEL > 0)
        ssl_set_dbg(ssl, polar_debug, 0);
#endif

#if (POLARSSL_VERSION_NUMBER < 0x01030000)
        ssl_set_own_cert(ssl, &server_context.cert, &thctx->rsa);
#else
        ssl_set_own_cert(ssl, &server_context.cert, &thctx->pkey);
        ssl_set_session_tickets(ssl, SSL_SESSION_TICKETS_ENABLED);
#endif
        ssl_set_ca_chain(ssl, &server_context.ca_cert, NULL, NULL);
        ssl_set_dh_param_ctx(ssl, &server_context.dhm);

	ssl_set_session_cache(ssl, polar_cache_get, &global_sessions,
			polar_cache_set, &global_sessions);

        ssl_set_bio(ssl, net_recv, &(*cur)->fd, net_send, &(*cur)->fd);
    }
    else {
        ssl = &(*cur)->context;
    }

    (*cur)->fd = fd;

    return ssl;
}

static int context_unset(int fd, ssl_context *ssl)
{
    struct polar_context_head *head;

    head = container_of(ssl, struct polar_context_head, context);

    if (head->fd == fd) {
        head->fd = -1;
        ssl_session_reset(ssl);
    }
    else {
        mk_err("[polarssl %d] Context already unset.", fd);
    }

    return 0;
}

int _mkp_network_io_read(int fd, void *buf, int count)
{
    ssl_context *ssl = context_get(fd);
    if (!ssl) {
        ssl = context_new(fd);
    }

    int ret =  handle_return(ssl_read(ssl, buf, count));
    return ret;
}

int _mkp_network_io_write(int fd, const void *buf, size_t count)
{
    ssl_context *ssl = context_get(fd);
    if (!ssl) {
        ssl = context_new(fd);
    }

    return handle_return(ssl_write(ssl, buf, count));
}

int _mkp_network_io_writev(int fd, struct mk_iov *mk_io)
{
    ssl_context *ssl = context_get(fd);
    const int iov_len = mk_io->iov_idx;
    const struct iovec *io = mk_io->io;
    const size_t len = mk_io->total_len;
    unsigned char *buf;
    size_t used = 0;
    int ret = 0, i;

    if (!ssl) {
        ssl = context_new(fd);
    }

    buf = mk_api->mem_alloc(len);
    if (buf == NULL) {
        mk_err("malloc failed: %s", strerror(errno));
        return -1;
    }

    for (i = 0; i < iov_len; i++) {
        memcpy(buf + used, io[i].iov_base, io[i].iov_len);
        used += io[i].iov_len;
    }

    assert(used == len);
    ret = ssl_write(ssl, buf, len);
    mk_api->mem_free(buf);

    return handle_return(ret);
}

int _mkp_network_io_send_file(int fd, int file_fd, off_t *file_offset,
        size_t file_count)
{
    ssl_context *ssl = context_get(fd);
    unsigned char *buf;
    ssize_t used, remain = file_count, sent = 0;
    int ret;

    if (!ssl) {
        ssl = context_new(fd);
    }

    buf = mk_api->mem_alloc(SENDFILE_BUF_SIZE);
    if (buf == NULL) {
        return -1;
    }

    do {
        used = pread(file_fd, buf, SENDFILE_BUF_SIZE, *file_offset);
        if (used == 0) {
            ret = 0;
        }
        else if (used < 0) {
            mk_err("[polarssl] Read from file failed: %s", strerror(errno));
            ret = -1;
        }
        else if (remain > 0) {
            ret = ssl_write(ssl, buf, used < remain ? used : remain);
        }
        else {
            ret = ssl_write(ssl, buf, used);
        }

        if (ret > 0) {
            if (remain > 0) {
                remain -= ret;
            }
            sent += ret;
            *file_offset += ret;
        }
    } while (ret > 0);

    mk_api->mem_free(buf);

    if (sent > 0) {
        return sent;
    }
    else {
        return handle_return(ret);
    }
}

int _mkp_network_io_close(int fd)
{
    ssl_context *ssl = context_get(fd);

    PLUGIN_TRACE("[fd %d] Closing connection", fd);

    if (ssl) {
        ssl_close_notify(ssl);
        context_unset(fd, ssl);
    }

    net_close(fd);

    return 0;
}

int _mkp_network_io_accept(int server_fd)
{
    int remote_fd;

#ifdef ACCEPT_GENERIC
    remote_fd = accept(server_fd, NULL, NULL);
    if (remote_fd != -1) {
        mk_api->socket_set_nonblocking(remote_fd);
    }
#else
    remote_fd = accept4(server_fd, NULL, NULL, SOCK_NONBLOCK);
#endif

    return remote_fd;
}

int _mkp_network_io_create_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int _mkp_network_io_connect(char *host, int port)
{
    int ret;
    int socket_fd = -1;
    char *port_str = 0;
    unsigned long len;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    mk_api->str_build(&port_str, &len, "%d", port);

    ret = getaddrinfo(host, port_str, &hints, &res);
    mk_api->mem_free(port_str);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }
    for(rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = _mkp_network_io_create_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if( socket_fd == -1) {
            mk_warn("Error creating client socket, retrying");
            continue;
        }

        if (connect(socket_fd,
                    (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == -1) {
            close(socket_fd);
            mk_err("Can't connect to %s, retrying", host);
            continue;
        }

        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

int _mkp_network_io_bind(int socket_fd, const struct sockaddr *addr, socklen_t addrlen, int backlog)
{
    int ret;

    ret = bind(socket_fd, addr, addrlen);

    if( ret == -1 ) {
        mk_warn("Error binding socket");
        return ret;
    }

    /*
     * Enable TCP_FASTOPEN by default: if for some reason this call fail,
     * it will not affect the behavior of the server, in order to succeed,
     * Monkey must be running in a Linux system with Kernel >= 3.7 and the
     * tcp_fastopen flag enabled here:
     *
     *     # cat /proc/sys/net/ipv4/tcp_fastopen
     *
     * To enable this feature just do:
     *
     *     # echo 1 > /proc/sys/net/ipv4/tcp_fastopen
     */
    if (mk_api->config->kernel_features & MK_KERNEL_TCP_FASTOPEN) {
        ret = mk_api->socket_set_tcp_fastopen(socket_fd);
        if (ret == -1) {
            mk_warn("Could not set TCP_FASTOPEN");
        }
    }

    ret = listen(socket_fd, backlog);

    if(ret == -1 ) {
        mk_warn("Error setting up the listener");
        return -1;
    }

    return ret;
}

int _mkp_network_io_server(int port, char *listen_addr, int reuse_port)
{
    int socket_fd = -1;
    int ret;
    char *port_str = 0;
    unsigned long len;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    mk_api->str_build(&port_str, &len, "%d", port);

    ret = getaddrinfo(listen_addr, port_str, &hints, &res);
    mk_api->mem_free(port_str);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }

    for(rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = _mkp_network_io_create_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if( socket_fd == -1) {
            mk_warn("Error creating server socket, retrying");
            continue;
        }

        mk_api->socket_set_tcp_nodelay(socket_fd);
        mk_api->socket_reset(socket_fd);

        /* Check if reuse port can be enabled on this socket */
        if (reuse_port == MK_TRUE &&
            (mk_api->config->kernel_features & MK_KERNEL_SO_REUSEPORT)) {
            ret = mk_api->socket_set_tcp_reuseport(socket_fd);
            if (ret == -1) {
                mk_warn("Could not use SO_REUSEPORT, using fair balancing mode");
                mk_api->config->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
            }
        }

        ret = _mkp_network_io_bind(socket_fd, rp->ai_addr, rp->ai_addrlen, MK_SOMAXCONN);

        if(ret == -1) {
            mk_err("Cannot listen on %s:%i\n", listen_addr, port);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

int _mkp_init(struct plugin_api **api, char *confdir)
{
    int fail = 0;
    struct polar_config conf;

    // Evil global config stuff.
    mk_api = *api;
    if (mk_api->config->transport_layer &&
        strcmp(mk_api->config->transport_layer, "polarssl")) {
        PLUGIN_TRACE("[polarssl] Not used as transport layer, unload.");
        return -1;
    }
    mk_api->config->transport = MK_TRANSPORT_HTTPS;


    memset(&conf, 0, sizeof(conf));
    if (config_parse(confdir, &conf)) {
        fail = -1;
    }

    server_context.config = conf;

    polar_init();

    return fail;
}

void _mkp_core_thctx(void)
{
    if (polar_thread_init(&server_context.config)) {
        abort();
    }
}

void _mkp_exit()
{
    polar_exit();
}
