/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301  USA
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

#if (POLARSSL_VERSION_NUMBER > 0x01020000)
#include <polarssl/ssl_cache.h>
#endif // POLARSSL_VERSION_NUMBER

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
#if (POLARSSL_VERSION_NUMBER < 0x01020000)
    ssl_session session;
#endif
    int fd;
    struct polar_context_head *_next;
};

struct polar_thread_context {
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;

    struct polar_context_head *contexts;

    struct mk_list _head;
};

struct polar_server_context {
    pthread_mutex_t _mutex;

    x509_cert srvcert;
    rsa_context rsa;
    dhm_context dhm;

    struct polar_thread_context threads;
};

static struct polar_server_context server_context = {
    ._mutex = PTHREAD_MUTEX_INITIALIZER,
};

static char *my_dhm_P =
    "E4004C1F94182000103D883A448B3F80" \
    "2CE4B44A83301270002C20D0321CFD00" \
    "11CCEF784C26A400F43DFB901BCA7538" \
    "F2C6B176001CF5A0FD16D2C48B1D0C1C" \
    "F6AC8E1DA6BCC3B4E1F96B0564965300" \
    "FFA1D0B601EB2800F489AA512C4B248C" \
    "01F76949A60BB7F00A40B1EAB64BDD48" \
    "E8A700D60B7F1200FA8E77B0A979DABF";

static char *my_dhm_G = "4";

#if (POLARSSL_VERSION_NUMBER < 0x01020000)
static int my_ciphersuites[] =
{
    SSL_EDH_RSA_AES_256_SHA,
    SSL_EDH_RSA_CAMELLIA_256_SHA,
    SSL_EDH_RSA_AES_128_SHA,
    SSL_EDH_RSA_CAMELLIA_128_SHA,
    SSL_RSA_AES_256_SHA,
    SSL_RSA_CAMELLIA_256_SHA,
    SSL_RSA_AES_128_SHA,
    SSL_RSA_CAMELLIA_128_SHA,
    SSL_RSA_RC4_128_SHA,
    SSL_RSA_RC4_128_MD5,
    0
};
#endif // POLARSSL_VERSION_NUMBER

static pthread_key_t local_context;

static struct polar_context_head **local_contexts(void)
{
    struct polar_thread_context *thctx = pthread_getspecific(local_context);
    assert(thctx != NULL);
    return &(thctx->contexts);
}

static ctr_drbg_context *local_drbg_context(void)
{
    struct polar_thread_context *thctx = pthread_getspecific(local_context);
    assert(thctx != NULL);
    return &thctx->ctr_drbg;
}

#if (POLAR_DEBUG_LEVEL > 0)
static void polar_debug(void *ctx, int level, const char *str)
{
    (void)ctx;

    if (level < POLAR_DEBUG_LEVEL) {
        mk_warn("%s", str);
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
                errno = EAGAIN;
                break;
            case POLARSSL_ERR_SSL_CONN_EOF:
                return 0;
            default:
                break;
        }
        return -1;
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
    free(conf_path);

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

    ret = x509parse_crtfile(&server_context.srvcert, conf->cert_file);
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));
        mk_err("[polarssl] Load cert '%s' failed: %s",
                conf->cert_file,
                err_buf);

#if defined(POLARSSL_CERTS_C)
        mk_warn("[polarssl] Using test certificates, "
                "please set 'CertificateFile' in polarssl.conf");

        ret = x509parse_crt(&server_context.srvcert,
                (unsigned char *)test_srv_crt, strlen(test_srv_crt));
        if (ret) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_err("[polarssl] Load built-in cert failed: %s", err_buf);
            return -1;
        }

        ret = x509parse_crt(&server_context.srvcert,
                (unsigned char *)test_ca_crt, strlen(test_ca_crt));
        if (ret) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_err("[polarssl] Load built-in ca cert failed: %s", err_buf);
            return -1;
        }
#else
        return -1;
#endif // defined(POLARSSL_CERTS_C)
    }
    else if (conf->cert_chain_file != NULL) {
        ret = x509parse_crtfile(&server_context.srvcert,
                conf->cert_chain_file);
        if (ret) {
            error_strerror(ret, err_buf, sizeof(err_buf));
            mk_warn("[polarssl] Load cert chain '%s' failed: %s",
                    conf->cert_chain_file,
                    err_buf);
        }
    }

    return 0;
}

static int polar_load_key(const struct polar_config *conf)
{
    char err_buf[72];
    int ret;

    assert(conf->key_file);

    ret = x509parse_keyfile(&server_context.rsa, conf->key_file, NULL);
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));
        mk_err("[polarssl] Load key '%s' failed: %s",
                conf->key_file,
                err_buf);

#if defined(POLARSSL_CERTS_C)
        mk_warn("[polarssl] Using test RSA key, "
                "please set 'RSAKeyFile' in polarssl.conf");

        ret = x509parse_key(&server_context.rsa,
                (unsigned char *)test_srv_key, strlen(test_srv_key), NULL, 0);
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

    ret = x509parse_dhmfile(&server_context.dhm, conf->dh_param_file);
    if (ret < 0) {
        error_strerror(ret, err_buf, sizeof(err_buf));
        mk_warn("[polarssl] Load DH parameters '%s' failed: %s",
                conf->dh_param_file,
                err_buf);

        mk_warn("[polarssl] Using built-in DH parameters, "
                "please generate '%s' using 'opessl dhparam -out \"%s\" 1024'.",
                conf->dh_param_file, conf->dh_param_file);
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

static int polar_init(const struct polar_config *conf)
{
    pthread_key_create(&local_context, NULL);

#if defined(POLARSSL_SSL_CACHE_C)
    pthread_mutex_lock(&global_sessions._mutex);
    ssl_cache_init(&global_sessions.cache);
    pthread_mutex_unlock(&global_sessions._mutex);
#endif

    pthread_mutex_lock(&server_context._mutex);
    mk_list_init(&server_context.threads._head);

    memset(&server_context.srvcert, 0, sizeof(server_context.srvcert));
    memset(&server_context.dhm, 0, sizeof(server_context.dhm));
    rsa_init(&server_context.rsa, RSA_PKCS_V15, 0);
    pthread_mutex_unlock(&server_context._mutex);

    PLUGIN_TRACE("[polarssl] Load certificates.");
    if (polar_load_certs(conf)) {
        return -1;
    }
    PLUGIN_TRACE("[polarssl] Load RSA key.");
    if (polar_load_key(conf)) {
        return -1;
    }
    PLUGIN_TRACE("[polarssl] Load DH parameters.");
    if (polar_load_dh_param(conf)) {
        return -1;
    }

    return 0;
}

static int polar_thread_init(void)
{
    struct polar_thread_context *thctx;
    int ret;

    PLUGIN_TRACE("[polarssl] Init thread context.");

    thctx = malloc(sizeof(*thctx));
    if (thctx == NULL) {
        return -1;
    }
    thctx->contexts = NULL;
    mk_list_init(&thctx->_head);

    pthread_mutex_lock(&server_context._mutex);
    mk_list_add(&thctx->_head, &server_context.threads._head);
    pthread_mutex_unlock(&server_context._mutex);

    PLUGIN_TRACE("[polarssl] Seed thread random number generator.");
    entropy_init(&thctx->entropy);

    ret = ctr_drbg_init(&thctx->ctr_drbg,
            entropy_func, &thctx->entropy,
            NULL, 0);
    if (ret) {
        mk_err("crt_drbg_init failed: %d", ret);
        free(thctx);
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
            free(cur);
        }

        ssl_free(&cur->context);
        memset(cur, 0, sizeof(*cur));
        free(cur);
    }
}

static void config_free(struct polar_config *conf)
{
    if (conf->cert_file) free(conf->cert_file);
    if (conf->cert_chain_file) free(conf->cert_chain_file);
    if (conf->key_file) free(conf->key_file);
    if (conf->dh_param_file) free(conf->dh_param_file);
}

static void polar_exit(void)
{
    struct mk_list *cur, *tmp;
    struct polar_thread_context *thctx;

    x509_free(&server_context.srvcert);
    rsa_free(&server_context.rsa);
    dhm_free(&server_context.dhm);

    mk_list_foreach_safe(cur, tmp, &server_context.threads._head) {
        thctx = mk_list_entry(cur, struct polar_thread_context, _head);
        contexts_free(thctx->contexts);
        free(thctx);
    }
    pthread_mutex_destroy(&server_context._mutex);

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free(&global_sessions.cache);
    pthread_mutex_destroy(&global_sessions._mutex);
#endif
}

static ssl_context *context_get(int fd)
{
    struct polar_context_head **cur = local_contexts();

    assert(cur != NULL);

    for (; *cur; cur = &(*cur)->_next) {
        if ((*cur)->fd == fd) {
            return &(*cur)->context;
        }
    }

    return NULL;
}

static ssl_context *context_new(int fd)
{
    struct polar_context_head **cur = local_contexts();
    ssl_context *ssl = NULL;

    assert(cur != NULL);

    for (; *cur; cur = &(*cur)->_next) {
        if ((*cur)->fd == -1) {
            break;
        }
    }

    if (*cur == NULL) {
        PLUGIN_TRACE("[polarssl %d] New ssl context.", fd);

        *cur = malloc(sizeof(**cur));
        if (*cur == NULL) {
            return NULL;
        }
        (*cur)->_next = NULL;

        ssl = &(*cur)->context;

        ssl_init(ssl);
        ssl_set_endpoint(ssl, SSL_IS_SERVER);
        ssl_set_authmode(ssl, SSL_VERIFY_NONE);

        ssl_set_rng(ssl, ctr_drbg_random, local_drbg_context());
#if (POLAR_DEBUG_LEVEL > 0)
        ssl_set_dbg(ssl, polar_debug, 0);
#endif

#if (POLARSSL_VERSION_NUMBER < 0x01020000)
        ssl_set_ciphersuites(ssl, my_ciphersuites);

        ssl_set_session(ssl, 0, 0, &(*cur)->session);
        memset(&(*cur)->session, 0, sizeof((*cur)->session));
#endif

        ssl_set_ca_chain(ssl, server_context.srvcert.next, NULL, NULL);
        ssl_set_own_cert(ssl, &server_context.srvcert, &server_context.rsa);
        ssl_set_dh_param_ctx(ssl, &server_context.dhm);

        ssl_set_bio(ssl, net_recv, &(*cur)->fd, net_send, &(*cur)->fd);
    }
    else {
        PLUGIN_TRACE("[polarssl %d] Reuse ssl context.", fd);

        ssl = &(*cur)->context;
        ssl_session_reset(ssl);
    }

    (*cur)->fd = fd;

    return ssl;
}

static int polar_unset_context(int fd, ssl_context *ssl)
{
    struct polar_context_head *head;

    head = container_of(ssl, struct polar_context_head, context);

    if (head->fd == fd) {
        head->fd = -1;
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

    return handle_return(ssl_read(ssl, buf, count));
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

    buf = malloc(len);
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
    free(buf);

    return handle_return(ret);
}

int _mkp_network_io_send_file(int fd, int file_fd, off_t *file_offset,
        size_t file_count)
{
    ssl_context *ssl = context_get(fd);
    unsigned char *buf;
    ssize_t used, remain = file_count, sent = 0;
    int ret;
#if defined(TRACE)
    char err_buf[72];
#endif

    if (!ssl) {
        ssl = context_new(fd);
    }

    buf = malloc(SENDFILE_BUF_SIZE);
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

    free(buf);

    if (sent > 0) {
        return sent;
    }
    else {
#if defined(TRACE)
        error_strerror(ret, err_buf, sizeof(err_buf));
        PLUGIN_TRACE("[polarssl] SSL error: %s", err_buf);
#endif
        switch( ret )
        {
            case POLARSSL_ERR_NET_WANT_READ:
            case POLARSSL_ERR_NET_WANT_WRITE:
                errno = EAGAIN;
            case POLARSSL_ERR_SSL_CONN_EOF:
                return 0;
            default:
                return -1;
        }
    }
}

int _mkp_network_io_close(int fd)
{
    ssl_context *ssl = context_get(fd);

    PLUGIN_TRACE("[fd %d] Closing connection", fd);

    if (ssl) {
        ssl_close_notify(ssl);
        polar_unset_context(fd, ssl);
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

    ret = listen(socket_fd, backlog);

    if(ret == -1 ) {
        mk_warn("Error setting up the listener");
        return -1;
    }

    return ret;
}

int _mkp_network_io_server(int port, char *listen_addr)
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
        ret = _mkp_network_io_bind(socket_fd, rp->ai_addr, rp->ai_addrlen, MK_SOMAXCONN);

        if(ret == -1) {
            mk_err("Port %i cannot be used, retrying\n", port);
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
    char *cwd;
    int fail = 0;
    struct polar_config conf;

    // Evil global config stuff.
    mk_api = *api;
    if (strcmp(mk_api->config->transport_layer, "polarssl")) {
        PLUGIN_TRACE("[polarssl] Not used as transport layer, unload.");
        return -1;
    }
    mk_api->config->transport = MK_TRANSPORT_HTTPS;

    cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        mk_err("[polarssl] Malloc failed: %s",
                strerror(errno));
        return -1;
    }
    if (chdir(confdir)) {
        mk_err("[polarssl] Failed to change working directory: %s",
                strerror(errno));
        free(cwd);
        return -1;
    }

    memset(&conf, 0, sizeof(conf));
    if (config_parse(confdir, &conf)) {
        fail = -1;
    }
    else if (polar_init(&conf)) {
        fail = -1;
    }

    config_free(&conf);
    chdir(cwd);
    free(cwd);
    return fail;
}

void _mkp_core_thctx(void)
{
    if (polar_thread_init()) {
        abort();
    }
}

void _mkp_exit()
{
    polar_exit();
}

