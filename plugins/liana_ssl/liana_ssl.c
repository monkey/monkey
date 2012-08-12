/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010-2011, Jonathan Gonzalez V. <zeus@gnu.org>
 *  Copyright (C)      2011, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>

#include "MKPlugin.h"

#include "liana_ssl.h"

/* Plugin data for register */
MONKEY_PLUGIN("liana_ssl", "Liana SSL Network", "0.2",
              MK_PLUGIN_CORE_PRCTX | MK_PLUGIN_CORE_THCTX | MK_PLUGIN_NETWORK_IO);

struct plugin_api *mk_api;

#define MK_LIANA_SSL_BUFFER_PLAIN SSL_MAX_PLAINTEXT_LEN
#define MK_LIANA_SSL_FATAL -2
#define MK_LIANA_SSL_WARNING -1
#define MK_LIANA_SSL_NO_ERROR 0

sslKeys_t *keys;
char *cert_file;
char *key_file;

pthread_key_t _data;
pthread_key_t _mkp_buffer_send_file;
pthread_key_t _mkp_buffer_write;
pthread_key_t _mkp_buffer_read;

int liana_ssl_error(int ret, unsigned char *error, struct mk_liana_ssl *conn) {
    unsigned long len;

    if (ret == MATRIXSSL_RECEIVED_ALERT) {
        if (*error == SSL_ALERT_LEVEL_FATAL) {
#ifdef TRACE
            PLUGIN_TRACE ("A fatal alert has raise, we must close the connection. Error %d", *(error + 1));
#endif
            ret = matrixSslProcessedData(conn->ssl, &error, (uint32 *)&len);

            return MK_LIANA_SSL_FATAL;
        } else if (*error == SSL_ALERT_LEVEL_WARNING) {
            PLUGIN_TRACE ("A warning ocurred while reading. Error %d", *(error + 1));
            ret = matrixSslProcessedData(conn->ssl, &error, (uint32 *)&len);

            return MK_LIANA_SSL_WARNING;
        }
    }

    return MK_LIANA_SSL_NO_ERROR;
}

int _mkp_network_io_close(int socket_fd)
{
    struct mk_list *list_head = (struct mk_list *) pthread_getspecific(_mkp_data);
    struct mk_list *curr, *temp;
    struct mk_liana_ssl *conn = NULL;

    PLUGIN_TRACE("Locating socket on ssl connections list to close");

    mk_list_foreach_safe(curr, temp, list_head) {
        if (curr == NULL) break;
        conn = mk_list_entry(curr, struct mk_liana_ssl, cons);
        if (conn->socket_fd == socket_fd) {
            close(socket_fd);
            return 0;
        }
        conn = NULL;
    }

    if (conn == NULL)
        return -1;

    return 0;
}


int liana_conf(char *confdir)
{
    int ret = 0;
    unsigned long len;
    char *conf_path = NULL;
    struct mk_config_section *section;
    struct mk_config *conf;
    struct mk_list *head;

    /* Read palm configuration file */
    mk_api->str_build(&conf_path, &len, "%s/liana_ssl.conf", confdir);
    conf = mk_api->config_create(conf_path);

    mk_list_foreach(head, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        /*
         * Just read PALM sections... yes it's a joke for edsiper XD
         *
         * edsiper says "i will start counting the number of Bazingas"
         *
         *  - Feb 13, 2012: +1
         */
        if (strcasecmp(section->name, "LIANA_SSL") != 0) {
            continue;
        }

        cert_file =
            mk_api->config_section_getval(section, "CertFile",
                                          MK_CONFIG_VAL_STR);

        PLUGIN_TRACE("Register Certificate File '%s'", cert_file);

        key_file =
            mk_api->config_section_getval(section, "KeyFile",
                                          MK_CONFIG_VAL_STR);

        PLUGIN_TRACE("Register Key File '%s'", key_file);
    }

    mk_api->mem_free(conf_path);

    return ret;
}

int liana_ssl_handshake(struct mk_liana_ssl *conn)
{
    unsigned char *buf = NULL;
    unsigned char *buf_sent = NULL;
    int len;
    int ret = 0;
    ssize_t bytes_read;
    ssize_t bytes_sent;

    PLUGIN_TRACE("Trying to handshake");
    while (ret != MATRIXSSL_HANDSHAKE_COMPLETE) {
        len = matrixSslGetReadbuf(conn->ssl, &buf);

        if (len == PS_ARG_FAIL) {
            PLUGIN_TRACE("Error trying to read data for handshake");
            return -1;
        }

        bytes_read = read(conn->socket_fd, (void *) buf, len);

        if (bytes_read < 0) {
            PLUGIN_TRACE("Error reading data from buffer");
            return -1;
        }

        PLUGIN_TRACE("Read %d data for handshake", bytes_read);

        ret =
            matrixSslReceivedData(conn->ssl, bytes_read,
                                  (unsigned char **) &buf, (uint32 *) & len);

        PLUGIN_TRACE("LOOP ret=%i", ret);

        if (ret == MATRIXSSL_REQUEST_RECV)
            continue;

        if (ret == PS_MEM_FAIL || ret == PS_ARG_FAIL || ret == PS_PROTOCOL_FAIL) {
            PLUGIN_TRACE("An error occurred while trying to decode the ssl data");
            return -1;
        }

        if (ret == MATRIXSSL_HANDSHAKE_COMPLETE) {
            PLUGIN_TRACE("Ssl handshake complete!");
            return 0;
        }

        if (ret == MATRIXSSL_REQUEST_SEND) {
            PLUGIN_TRACE("The handshake needs to send data");
            do {
                len = matrixSslGetOutdata(conn->ssl, &buf_sent);

                if (len == 0)
                    break;

                if (len == PS_ARG_FAIL) {
                    PLUGIN_TRACE
                        ("Error trying to send data during the handshake");
                    return -1;
                }

                bytes_sent = write(conn->socket_fd, (void *) buf_sent, len);
                if (bytes_sent == -1) {
                    PLUGIN_TRACE("An error ocurred trying to send data");
                    return -1;
                }
                PLUGIN_TRACE("Has sent %d of %d data to end the handshake ",
                             bytes_sent, len);

                ret = matrixSslSentData(conn->ssl, (uint32) bytes_sent);

                if (ret == MATRIXSSL_REQUEST_CLOSE) {
                    PLUGIN_TRACE("Success we should close the session, why?");
                    return -1;
                }

                if (ret == PS_ARG_FAIL) {
                    PLUGIN_TRACE("Error sending data during handshake");
                    return -1;
                }

            } while (ret != MATRIXSSL_SUCCESS
                     || ret != MATRIXSSL_HANDSHAKE_COMPLETE);
        }
    }

    PLUGIN_TRACE("Handshake complete!");
    return 0;
}

int liana_ssl_close(struct mk_liana_ssl *conn)
{
    int len;
    int ret;
    unsigned char *buf_close;

    ret = matrixSslEncodeClosureAlert (conn->ssl);

    if( ret == MATRIXSSL_ERROR || ret == PS_ARG_FAIL || ret == PS_MEM_FAIL) return -1;

    len = matrixSslGetOutdata (conn->ssl, &buf_close);

    ret = write (conn->socket_fd, (void *)buf_close, len);

    if(ret != len) return -1;


    return 0;
}

static void liana_ssl_version_error()
{
    mk_err("Liana_SSL requires MatrixSSL >= %i.%i.%i",
           MATRIXSSL_VERSION_MAJOR,
           MATRIXSSL_VERSION_MINOR,
           MATRIXSSL_VERSION_PATCH);
}

int _mkp_init(struct plugin_api **api, char *confdir)
{
    mk_api = *api;
    config_dir = mk_api->str_dup(confdir);

    /* Just load the plugin if is being used as transport layer */
    if (strcmp(mk_api->config->transport_layer, "liana_ssl") != 0) {
        mk_warn("Liana_SSL loaded but not used. Unloading.");
        return -1;
    }

    /* Validate MatrixSSL linked version */
    if (MK_MATRIX_REQUIRE_MAJOR > MATRIXSSL_VERSION_MAJOR) {
        liana_ssl_version_error();
        return -1;
    }
    if (MK_MATRIX_REQUIRE_MINOR > MATRIXSSL_VERSION_MINOR) {
        liana_ssl_version_error();
        return -1;
    }
    if (MK_MATRIX_REQUIRE_PATCH > MATRIXSSL_VERSION_PATCH) {
        liana_ssl_version_error();
        return -1;
    }

    return 0;
}

void _mkp_exit()
{
}

int _mkp_network_io_accept(int server_fd)
{
    int remote_fd;
    struct sockaddr_in sock_addr;
    socklen_t socket_size = sizeof(struct sockaddr);

    PLUGIN_TRACE("Accepting Connection");

    remote_fd =
        accept(server_fd, &sock_addr, &socket_size);

    if (remote_fd == -1) {
        PLUGIN_TRACE("Error accepting connection");
        return -1;
    }

    return remote_fd;
}

int _mkp_network_io_read(int socket_fd, void *buf, int count)
{
    ssize_t bytes_read;
    struct mk_list *list_head = (struct mk_list *) pthread_getspecific(_mkp_data);
    struct mk_list *curr;
    struct mk_liana_ssl *conn = NULL;
    int ret;
    int len;
    unsigned char *buf_ssl = NULL;
    int pending = 0;

    PLUGIN_TRACE("Locating socket on ssl connections list");

    mk_list_foreach(curr, list_head) {
        if (curr == NULL) break;
        conn = mk_list_entry(curr, struct mk_liana_ssl, cons);
        if (conn->socket_fd == socket_fd)
            break;
        conn = NULL;
    }
    if (conn == NULL)
        return -1;

    PLUGIN_TRACE("Reading");

    ret = ioctl(socket_fd, FIONREAD, &pending);

    do {
        len = matrixSslGetReadbuf(conn->ssl, &buf_ssl);

        if( len == PS_ARG_FAIL) {
            PLUGIN_TRACE ("Error locatting buffer to read");
        }

        if (len == 0) return 0;

        bytes_read = read(socket_fd, (void *) buf_ssl, len);
        PLUGIN_TRACE("Decoding data from ssl connection");

        ret =
            matrixSslReceivedData(conn->ssl, bytes_read,
                                  (unsigned char **) &buf_ssl,
                                  (uint32 *) & len);
        if (ret == PS_MEM_FAIL || ret == PS_ARG_FAIL || ret == PS_PROTOCOL_FAIL) {
            PLUGIN_TRACE
                ("An error occurred while trying to decode the ssl data");

            matrixSslProcessedData(conn->ssl, &buf_ssl, (uint32 *)&len);
            _mkp_network_io_close(socket_fd);
            return -1;
        }

    } while (ret == MATRIXSSL_REQUEST_RECV && ret != MATRIXSSL_RECEIVED_ALERT);

    ret = liana_ssl_error(ret, buf_ssl, conn);

    if (ret != MK_LIANA_SSL_NO_ERROR) {
        return -1;
    }

    if (ret == MATRIXSSL_REQUEST_SEND ) {
        PLUGIN_TRACE ("We must sent data to the peer? that's odd");
        len = matrixSslGetOutdata(conn->ssl, (unsigned char **)&buf_ssl);
    }

    if( buf_ssl == NULL) return 0;

    strncpy((char *) buf, (const char *) buf_ssl, count);
    bytes_read = len;

    ret = matrixSslProcessedData(conn->ssl, &buf_ssl, (uint32 *)&len);

    return bytes_read;
}

int _mkp_network_io_write(int socket_fd, const void *buf, size_t count)
{
    ssize_t bytes_sent = -1;
    ssize_t bytes_written;
    struct mk_list *list_head = (struct mk_list *) pthread_getspecific(_mkp_data);
    struct mk_list *curr;
    struct mk_liana_ssl *conn = NULL;
    char *buf_plain = NULL;
    unsigned char *buf_ssl = NULL;
    int ret;
    int len;

    if (buf == NULL)
        return 0;

    PLUGIN_TRACE("Write");

    mk_list_foreach(curr, list_head) {
        if (curr == NULL) break;
        conn = mk_list_entry(curr, struct mk_liana_ssl, cons);
        if (conn->socket_fd == socket_fd)
            break;
        conn = NULL;
    }
    if (conn == NULL)
        return -1;

    len = matrixSslGetWritebuf(conn->ssl, (unsigned char **) &buf_plain, count);

    if (len == PS_MEM_FAIL || len == PS_ARG_FAIL || len == PS_FAILURE) {
        PLUGIN_TRACE("Can't allocate memory for plain content");
        return -1;
    }

    if( len < count ) {
        bytes_sent = len;
    } else {
        bytes_sent = count;
    }

    buf_plain = memmove(buf_plain, buf, bytes_sent);

    len = matrixSslEncodeWritebuf(conn->ssl, bytes_sent);

    if (len == PS_ARG_FAIL || len == PS_PROTOCOL_FAIL || len == PS_FAILURE) {
        PLUGIN_TRACE("Failed while encoding message");
        return -1;
    }

    do {
        len = matrixSslGetOutdata(conn->ssl, (unsigned char **) &buf_ssl);

        if (len == PS_ARG_FAIL) {
            PLUGIN_TRACE("Error encoding data to send");
            return -1;
        }

        if (len == 0 ) {
            PLUGIN_TRACE ("There's no left data to sent");
            return bytes_sent;
        }

        bytes_written = write(socket_fd, buf_ssl, len);
        ret = matrixSslSentData(conn->ssl, bytes_written);

    } while(ret != MATRIXSSL_SUCCESS);

    return bytes_sent;
}

int _mkp_network_io_writev(int socket_fd, struct mk_iov *mk_io)
{
    int i;
    int count = 0;
    ssize_t bytes_sent = -1;
    char *buffer_write = (char *) pthread_getspecific(_mkp_buffer_write);

    PLUGIN_TRACE("WriteV");

    /* Move iov array data to string buffer */
    for (i = 0; i < mk_io->iov_idx; i++) {
        strncpy(buffer_write + count, mk_io->io[i].iov_base, mk_io->io[i].iov_len);
        count += mk_io->io[i].iov_len;
    }
    buffer_write[count] = '\0';

    /* Debug */
    PLUGIN_TRACE("preparing buffer of %i bytes", count);

    /* Write data */
    bytes_sent = _mkp_network_io_write(socket_fd, buffer_write, count);
    PLUGIN_TRACE("written %i bytes", bytes_sent);

    return bytes_sent;
}

int _mkp_network_io_create_socket(int domain, int type, int protocol)
{
    int socket_fd;

    PLUGIN_TRACE("Creating Socket");
    socket_fd = socket(domain, type, protocol);

    return socket_fd;
}

int _mkp_network_io_connect(char *host, int port)
{
    int ret;
    int socket_fd = 0;
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
            mk_warn("Error creating client socket");
            return -1;
        }

        if (connect(socket_fd,
                    (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == -1) {
            close(socket_fd);
            mk_err("Can't connect to %s", host);
            return -1;
        }

        break;
    }
    freeaddrinfo(res);

    return socket_fd;
}

int _mkp_network_io_send_file(int socket_fd, int file_fd, off_t * file_offset,
                              size_t file_count)
{
    ssize_t bytes_written = -1;
    char *buffer_send_file = (char *) pthread_getspecific(_mkp_buffer_send_file);
    ssize_t len;

    PLUGIN_TRACE("Send file");

    len = pread(file_fd, buffer_send_file, MK_LIANA_SSL_BUFFER_PLAIN, *file_offset);
    if (len == -1) return -1;

    bytes_written = _mkp_network_io_write(socket_fd, buffer_send_file, len);
    if (bytes_written != -1 ) *file_offset += bytes_written;

    return bytes_written;
}

int _mkp_network_io_bind(int socket_fd, const struct sockaddr *addr,
                         socklen_t addrlen, int backlog)
{
    int ret;

    ret = bind(socket_fd, addr, addrlen);

    if (ret == -1) {
        PLUGIN_TRACE ("Error binding socket");
        return ret;
    }

    ret = listen(socket_fd, backlog);

    if (ret == -1) {
        PLUGIN_TRACE ("Error setting up the listener");
        return -1;
    }

    return ret;
}

int _mkp_network_io_server(int port, char *listen_addr)
{
    int socket_fd = 0;
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
            mk_warn("Error creating server socket");
            return -1;
        }

        mk_api->socket_set_tcp_nodelay(socket_fd);
        mk_api->socket_reset(socket_fd);
        ret = _mkp_network_io_bind(socket_fd, rp->ai_addr, rp->ai_addrlen, MK_SOMAXCONN);

        if(ret == -1) {
            mk_err("Port %i cannot be used\n", port);
            return -1;
        }
        break;
    }
    freeaddrinfo(res);

    return socket_fd;
}

int _mkp_core_prctx(struct server_config *config)
{
    struct file_info ssl_file_info;

    /* set Monkey transport layer type */
    mk_api->config->transport = MK_TRANSPORT_HTTPS;

    /* load configuration */
    liana_conf(config_dir);

    /* Enable server safe event write */
    config->safe_event_write = MK_TRUE;

    if (matrixSslOpen() < 0) {
        mk_err("Liana_SSL: Can't start matrixSsl");
        exit(EXIT_FAILURE);
    }

    PLUGIN_TRACE("MatrixSsl Started");

    if (matrixSslNewKeys(&keys) < 0) {
        mk_err("MatrixSSL couldn't init the keys");
        exit(EXIT_FAILURE);
    }

    if (!cert_file) {
        mk_err("Liana_SSL: No certificate defined");
        exit(EXIT_FAILURE);
    }

    if (mk_api->file_get_info(cert_file, &ssl_file_info) == -1) {
        mk_err("Liana_SSL: Cannot read certificate file '%s'", cert_file);
        exit(EXIT_FAILURE);
    }

    if (mk_api->file_get_info(key_file, &ssl_file_info) == -1) {
        mk_err("Liana_SSL: Cannot read key file '%s'", key_file);
        exit(EXIT_FAILURE);
    }

    if (matrixSslLoadRsaKeys(keys, cert_file, key_file, NULL, NULL) < 0) {
        mk_err("Liana_SSL: MatrixSsl couldn't read the certificates");
        exit(EXIT_FAILURE);
    }

    PLUGIN_TRACE("MatrixSsl just read the certificates, ready to go!");

    pthread_key_create(&_mkp_data, NULL);
    pthread_key_create(&_mkp_buffer_send_file, NULL);
    pthread_key_create(&_mkp_buffer_write, NULL);
    pthread_key_create(&_mkp_buffer_read, NULL);


    return 0;
}

void _mkp_core_thctx()
{
    struct mk_list *list_head = mk_api->mem_alloc(sizeof(struct mk_list));
    char *buffer_send_file = mk_api->mem_alloc_z(MK_LIANA_SSL_BUFFER_PLAIN * sizeof(char));
    char *buffer_write = mk_api->mem_alloc_z(MK_LIANA_SSL_BUFFER_PLAIN * sizeof(char));
    char *buffer_read = mk_api->mem_alloc_z(MK_LIANA_SSL_BUFFER_PLAIN * sizeof(char));

    PLUGIN_TRACE ("Creating pthread keys");
    mk_list_init(list_head);

    pthread_setspecific(_mkp_data, list_head);
    pthread_setspecific(_mkp_buffer_send_file, buffer_send_file);
    pthread_setspecific(_mkp_buffer_write, buffer_write);
    pthread_setspecific(_mkp_buffer_read, buffer_read);

}

int _mkp_event_read(int socket_fd)
{
    int ret;
    struct mk_list *list_head = (struct mk_list *) pthread_getspecific(_mkp_data);
    struct mk_list *curr;
    struct mk_liana_ssl *conn;

    mk_list_foreach(curr, list_head) {
        if (curr == NULL) return MK_PLUGIN_RET_EVENT_NEXT;
        conn = mk_list_entry(curr, struct mk_liana_ssl, cons);

        if (conn->socket_fd == socket_fd)
            return MK_PLUGIN_RET_EVENT_NEXT;
    }

    conn = (struct mk_liana_ssl *) malloc(sizeof(struct mk_liana_ssl));

    if ((ret = matrixSslNewServerSession(&conn->ssl, keys, NULL)) < 0) {
        PLUGIN_TRACE("Error initiating the ssl session");
        matrixSslDeleteSession(conn->ssl);
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    PLUGIN_TRACE("Ssl session started");

    conn->socket_fd = socket_fd;

    mk_list_add(&conn->cons, list_head);
    pthread_setspecific(_mkp_data, list_head);
    ret = liana_ssl_handshake(conn);

    if (ret != 0) {
        PLUGIN_TRACE("Error trying to handshake with the client");
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    return MK_PLUGIN_RET_EVENT_NEXT;
}

int _mkp_event_close(int socket_fd)
{
    struct mk_list *list_head = (struct mk_list *) pthread_getspecific(_mkp_data);
    struct mk_list *curr, *temp;
    struct mk_liana_ssl *conn = NULL;

    PLUGIN_TRACE("Locating socket on ssl connections list");

    mk_list_foreach_safe(curr, temp, list_head) {
        if (curr == NULL) break;
        conn = mk_list_entry(curr, struct mk_liana_ssl, cons);
        if (conn->socket_fd == socket_fd) {

            liana_ssl_close (conn);

            matrixSslDeleteSession (conn->ssl);
            mk_list_del(curr);
            pthread_setspecific(_mkp_data, list_head);
            return MK_PLUGIN_RET_EVENT_CONTINUE;
        }
    }

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}


int _mkp_event_timeout(int socket_fd)
{
    PLUGIN_TRACE ("Event timeout");
    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int _mkp_event_error(int socket_fd)
{
    PLUGIN_TRACE ("Event error");
    return MK_PLUGIN_RET_EVENT_CONTINUE;
}
