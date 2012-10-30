/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010-2011, Jonathan Gonzalez V. <zeus@gnu.org>
 *  Copyright (C)      2011, Eduardo Silva P. <edsiper@gmail.com>
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
 *  MA 02110-1301  USA.
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

sslKeys_t *matrixssl_keys;
char *cert_file;
char *key_file;

pthread_key_t _data;
pthread_key_t _mkp_buffer_send_file;

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

struct mk_liana_ssl *liana_ssl_get_connection(int socket_fd)
{
    struct mk_list *list_head = pthread_getspecific(_mkp_data);
    struct mk_list *curr;
    struct mk_liana_ssl *conn;

    mk_list_foreach(curr, list_head) {
	    conn = mk_list_entry(curr, struct mk_liana_ssl, cons);
	    if (socket_fd == conn->socket_fd) {
		    return conn;
	    }
    }
    return NULL;
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

int _mkp_network_io_close(int socket_fd)
{
    struct mk_liana_ssl *conn = NULL;

    conn = liana_ssl_get_connection(socket_fd);

    if (conn == NULL) {
        return -1;
    }
    else {
        close(conn->socket_fd);
        return 0;
    }
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
	matrixSslClose();
}

int _mkp_network_io_accept(int server_fd)
{
    int remote_fd;
    struct sockaddr sock_addr;
    socklen_t socket_size = sizeof(struct sockaddr);

#ifdef ACCEPT_GENERIC
    remote_fd = accept(server_fd, &sock_addr, &socket_size);
    mk_api->socket_set_nonblocking(remote_fd);
#else
    remote_fd = accept4(server_fd, &sock_addr, &socket_size, SOCK_NONBLOCK);
#endif

    return remote_fd;
}

int liana_ssl_handle_alert(struct mk_liana_ssl *conn)
{
	char alert_b0 = *(conn->buf_ssl + 0);
	char alert_b1 = *(conn->buf_ssl + 1);

	conn->buf_used += 2;

	switch (alert_b0) {
	case SSL_ALERT_LEVEL_WARNING:
		switch (alert_b1) {
		case 0:
			PLUGIN_TRACE("[FD %d] Warning, client close.",
					conn->socket_fd);
			return 0;
		default:
			mk_warn("[liana_ssl] Warning %d on fd %d.",
					alert_b1, conn->socket_fd);
			return 0;
		}
	case SSL_ALERT_LEVEL_FATAL:
		mk_err("[liana_ssl] Fatal error %d on fd %d.",
				alert_b1, conn->socket_fd);
		_mkp_network_io_close(conn->socket_fd);
		return -1;
	case SSL_ALERT_CLOSE_NOTIFY:
		PLUGIN_TRACE("Received close notify.");
		_mkp_network_io_close(conn->socket_fd);
		return -1;
	default:
		mk_info("[liana_ssl] Unknown alert received: %d, %d on fd %d",
				alert_b0, alert_b1, conn->socket_fd);
		return 0;
	}
}

int liana_ssl_handle_remain(struct mk_liana_ssl *conn,
		unsigned char *buf,
		uint32_t count)
{
	size_t remain = conn->buf_len - conn->buf_used;
	remain = remain > count ? count : remain;

	if (count == 0 || conn->buf_len <= conn->buf_used || remain == 0) {
		return 0;
	}
	PLUGIN_TRACE("Read from already received buffer.");

	memcpy(buf, conn->buf_ssl + conn->buf_used, remain);
	conn->buf_used += remain;

	return remain;
}

static int liana_ssl_handle_socket_read(struct mk_liana_ssl *conn)
{
	ssize_t bytes_read;
	int ret;

	if (conn->try_false_start) {
		ret = matrixSslReceivedData(conn->ssl,
				0,
				&conn->buf_ssl,
				&conn->buf_len);

		if (ret < 0) {
			mk_err("[liana_ssl] Failed to false start.");
		}
		else if (ret == PS_SUCCESS) {
			PLUGIN_TRACE("[FD %d] No false start.",
					conn->socket_fd);
			conn->need_read = 1;
		}
		else {
			PLUGIN_TRACE("[FD %d] Do false start.",
					conn->socket_fd);
			conn->need_read = 0;
		}
		conn->try_false_start = 0;
	}

	if (conn->need_read == 1) {
		PLUGIN_TRACE("[FD %d] SSL connection needs more data.",
				conn->socket_fd);

		ret = matrixSslGetReadbuf(conn->ssl, &conn->buf_ssl);

		if (ret == PS_ARG_FAIL) {
			mk_err("[liana_ssl] Error locating SSL buffer.");
			return ret;
		}
		else if (ret == 0) {
			mk_err("[liana_ssl] SSL buffer space exhausted.");
			return PS_MEM_FAIL;
		}
		else {
			conn->buf_len = ret;
			conn->buf_used = ret;
		}

		bytes_read = read(conn->socket_fd, conn->buf_ssl, conn->buf_len);

		if (bytes_read == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				PLUGIN_TRACE("[FD %d] EAGAIN.", conn->socket_fd);
				return -1;
			}
			else {
				mk_err("[liana_ssl] Socket error: %s.", strerror(errno));
				return -1;
			}
		}
		else if (bytes_read == 0) {
			PLUGIN_TRACE("[FD %d] Connection done, force close.",
					conn->socket_fd);
			return -1;
		}

		PLUGIN_TRACE("[FD %d] Read %ld bytes.", conn->socket_fd, bytes_read);
		ret = matrixSslReceivedData(conn->ssl,
				bytes_read,
				&conn->buf_ssl,
				&conn->buf_len);

		if (conn->ssl->flags & SSL_FLAGS_FALSE_START &&
				!conn->handshake_complete) {
			PLUGIN_TRACE("[FD %d] Just got a false start.",
					conn->socket_fd);
			conn->try_false_start = 1;
		}

		conn->buf_used = 0;
		conn->need_read = 0;
	}
	else {
		ret = matrixSslProcessedData(conn->ssl,
				&conn->buf_ssl,
				&conn->buf_len);
		conn->buf_used = 0;
	}
	return ret;
}

int liana_ssl_handle_read(struct mk_liana_ssl *conn, unsigned char *buf, uint32_t count)
{
	ssize_t used = 0, remain;
	int ret;

	used += liana_ssl_handle_remain(conn, buf, count);

	PLUGIN_TRACE("Remain used: %ld.", used);

	do {
		ret = liana_ssl_handle_socket_read(conn);

		if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (used > 0) {
				goto end_read;
			}
			else {
				return -1;
			}
		}
		else if (ret == -1) {
			return -1;
		}

		switch (ret) {
		case PS_MEM_FAIL:
		case PS_ARG_FAIL:
			mk_err("[liana_ssl] MatrixSSL made a bo-bo on fd %d.",
					conn->socket_fd);
			return -1;

		case PS_PROTOCOL_FAIL:
			mk_err("[liana_ssl] SSL error no fd %d.",
					conn->socket_fd);
			_mkp_network_io_close(conn->socket_fd);
			return -1;

		case PS_SUCCESS:
			PLUGIN_TRACE("[FD %d] SSL records all processed.",
					conn->socket_fd);
			conn->need_read = 1;
			conn->buf_used = conn->buf_len;
			goto end_read;


		case MATRIXSSL_REQUEST_RECV:
			PLUGIN_TRACE("[FD %d] Should receive next read.",
					conn->socket_fd);
			conn->need_read = 1;
			break;

		case MATRIXSSL_REQUEST_SEND:
			PLUGIN_TRACE("[FD %d] Need to send ssl.",
					conn->socket_fd);
			conn->need_write = 1;
			// Try to write, need_write will be unset on
			// success.
			_mkp_event_write(conn->socket_fd);
			break;

		case MATRIXSSL_HANDSHAKE_COMPLETE:
			PLUGIN_TRACE("[FD %d] SSL normal handshake complete.",
					conn->socket_fd);
			conn->handshake_complete = 1;
			break;

		case MATRIXSSL_RECEIVED_ALERT:
			PLUGIN_TRACE("[FD %d] Handle alert.",
					conn->socket_fd);

			ret = liana_ssl_handle_alert(conn);
			if (ret == -1) {
				return -1;
			}
			break;

		case MATRIXSSL_APP_DATA:
			PLUGIN_TRACE("[FD %d] Handle app data %d bytes.",
					conn->socket_fd, conn->buf_len);
			if (!conn->handshake_complete) {
				PLUGIN_TRACE("[FD %d] Handshake complete.",
						conn->socket_fd);
				conn->handshake_complete = 1;
			}
			if (!buf) {
				goto end_read;
			}

			remain = count - used;
			remain = remain < conn->buf_len ? remain : conn->buf_len;

			memcpy(buf + used, conn->buf_ssl, remain);
			conn->buf_used += remain;

			used += remain;
			break;

		default:
			mk_err("[liana_ssl] Unknown record type on fd %d, ret %d.",
					conn->socket_fd, ret);
			return -1;
		}
	} while (count > used || !buf);

end_read:
	PLUGIN_TRACE("[FD %d] %d bytes read.", conn->socket_fd, used);
	PLUGIN_TRACE("'''\n%.*s\n'''", used, buf);
	return used;
}

int _mkp_network_io_read(int socket_fd, void *buf, int count)
{
    struct mk_liana_ssl *conn = NULL;

    conn = liana_ssl_get_connection(socket_fd);

    if (conn == NULL) {
        return -1;
    }
    else {
        return liana_ssl_handle_read(conn, buf, count);
    }
}

int _mkp_network_io_write(int socket_fd, const void *buf, size_t count)
{
    ssize_t bytes_sent = -1;
    struct mk_liana_ssl *conn = NULL;
    char *buf_plain = NULL;
    int ret;
    size_t len;

    if (buf == NULL)
        return 0;

    PLUGIN_TRACE("Write");

    conn = liana_ssl_get_connection(socket_fd);

    if (conn == NULL)
        return -1;

    ret = matrixSslGetWritebuf(conn->ssl, (unsigned char **) &buf_plain, count);

    if (ret == PS_MEM_FAIL || ret == PS_ARG_FAIL || ret == PS_FAILURE) {
        PLUGIN_TRACE("Can't allocate memory for plain content");
        return -1;
    } else {
	len = ret;
    }

    if( len < count ) {
        bytes_sent = len;
    } else {
        bytes_sent = count;
    }

    buf_plain = memmove(buf_plain, buf, bytes_sent);

    ret = matrixSslEncodeWritebuf(conn->ssl, bytes_sent);

    if (ret == PS_ARG_FAIL || ret == PS_PROTOCOL_FAIL || ret == PS_FAILURE) {
        PLUGIN_TRACE("Failed while encoding message");
        return -1;
    }

    conn->need_write = 1;
    _mkp_event_write(socket_fd);

    return bytes_sent;
}

int _mkp_network_io_writev(int socket_fd, struct mk_iov *mk_io)
{
    struct mk_liana_ssl *conn;
    size_t pos = 0, size = 0;
    unsigned char *buf_ssl;
    int ret, i;



    conn = liana_ssl_get_connection(socket_fd);

    if (!conn) {
	    return -1;
    }

    for (i = 0; i < mk_io->iov_idx; i++) {
	    size += mk_io->io[i].iov_len;
    }

    PLUGIN_TRACE("Writev with %ld bytes.", size);

    if (size == 0) {
	    return 0;
    }

    ret = matrixSslGetWritebuf(conn->ssl, &buf_ssl, size);

    if (ret == PS_MEM_FAIL || ret == PS_ARG_FAIL || ret == PS_FAILURE) {
	    mk_err("[liana_ssl] Failed to create write buffer.");
	    return -1;
    }

    for (i = 0; i < mk_io->iov_idx; i++) {
	    memcpy(buf_ssl + pos, mk_io->io[i].iov_base, mk_io->io[i].iov_len);
	    pos += mk_io->io[i].iov_len;
    }

    if (pos != size) {
	    mk_err("[liana_ssl] Counting is hard.");
	    abort();
    }

    ret = matrixSslEncodeWritebuf(conn->ssl, size);

    if (ret == PS_MEM_FAIL || ret == PS_ARG_FAIL || ret == PS_FAILURE) {
	    mk_err("[liana_ssl] Failed to encode write buffer.");
	    return -1;
    }

    return size;
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
    (void)file_count;

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
    (void)config;

    /* set Monkey transport layer type */
    mk_api->config->transport = MK_TRANSPORT_HTTPS;

    /* load configuration */
    liana_conf(config_dir);

    /* Enable server safe event write */
    //config->safe_event_write = MK_TRUE;

    if (matrixSslOpen() < 0) {
        mk_err("Liana_SSL: Can't start matrixSsl");
        exit(EXIT_FAILURE);
    }

    PLUGIN_TRACE("MatrixSsl Started");

    if (matrixSslNewKeys(&matrixssl_keys) < 0) {
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

    if (matrixSslLoadRsaKeys(matrixssl_keys, cert_file, key_file, NULL, NULL) < 0) {
        mk_err("Liana_SSL: MatrixSsl couldn't read the certificates");
        exit(EXIT_FAILURE);
    }

    PLUGIN_TRACE("MatrixSsl just read the certificates, ready to go!");

    pthread_key_create(&_mkp_data, NULL);
    pthread_key_create(&_mkp_buffer_send_file, NULL);


    return 0;
}

void _mkp_core_thctx()
{
    struct mk_list *list_head = mk_api->mem_alloc(sizeof(struct mk_list));
    char *buffer_send_file = mk_api->mem_alloc_z(MK_LIANA_SSL_BUFFER_PLAIN * sizeof(char));

    PLUGIN_TRACE ("Creating pthread keys");
    mk_list_init(list_head);

    pthread_setspecific(_mkp_data, list_head);
    pthread_setspecific(_mkp_buffer_send_file, buffer_send_file);

}

struct mk_liana_ssl *liana_ssl_new_connection(int socket_fd)
{
	struct mk_liana_ssl *conn;
	int ret;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		mk_err("[liana_ssl] Malloc error: %s.", strerror(errno));
		return NULL;
	}

	conn->buf_ssl = NULL;
	conn->buf_len = 0;
	conn->buf_used = 0;
	conn->handshake_complete = 0;
	conn->need_read = 1;
	conn->need_write = 0;
	conn->try_false_start = 0;
	conn->socket_fd = socket_fd;

	ret = matrixSslNewServerSession(&conn->ssl, matrixssl_keys, NULL);

	switch (ret) {
	case PS_SUCCESS:
		break;
	case PS_ARG_FAIL:
		mk_err("[liana_ssl] Bad input argument for NewServerSession.");
		free(conn);
		return NULL;
	case PS_FAILURE:
		mk_err("[liana_ssl] Failed to create new server session.");
		free(conn);
		return NULL;
	default:
		mk_err("[liana_ssl] Unknown error creating new server session.");
	}

	return conn;
}

int _mkp_event_read(int socket_fd)
{
	struct mk_list *list_head = pthread_getspecific(_mkp_data);
	struct mk_liana_ssl *conn;
	ssize_t ret = 0;

	conn = liana_ssl_get_connection(socket_fd);

	if (!conn) {
		PLUGIN_TRACE("[FD %d] Creating new SSL server session.",
				socket_fd);
		conn = liana_ssl_new_connection(socket_fd);
		mk_list_add(&conn->cons, list_head);
		return MK_PLUGIN_RET_EVENT_NEXT;
	}

	if (!conn->handshake_complete) {
		PLUGIN_TRACE("[FD %d] Event read.", socket_fd);

		ret = liana_ssl_handle_read(conn, NULL, 0);

		if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			mk_err("[liana_ssl] Socket error on %d: %s.",
					socket_fd, strerror(errno));
			return MK_PLUGIN_RET_EVENT_CLOSE;
		}

		if (conn->need_write) {
			_mkp_event_write(socket_fd);

			if (conn->need_write) {
				mk_api->event_socket_change_mode(conn->socket_fd,
						MK_EPOLL_RW,
						MK_EPOLL_LEVEL_TRIGGERED);
			}

			/* If the handshake completed during write,
			 * there is a high probability of FALSE_START
			 * and we must preserve the event.
			 */
			if (conn->handshake_complete) {
				return MK_PLUGIN_RET_EVENT_NEXT;
			}
		}
		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else {
		if (conn->need_write) {
			mk_api->event_socket_change_mode(conn->socket_fd,
					MK_EPOLL_RW,
					MK_EPOLL_LEVEL_TRIGGERED);
		}

		return MK_PLUGIN_RET_EVENT_NEXT;
	}
}

int _mkp_event_write(int socket_fd)
{
	struct mk_liana_ssl *conn;
	ssize_t bytes_sent;
	int32_t ret = 0;
	unsigned char *buf_ssl;
	uint32_t len;
	int done = 0, should_close = 0;

	conn = liana_ssl_get_connection(socket_fd);

	if (!conn || !conn->need_write) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}

	do {
		ret = matrixSslGetOutdata(conn->ssl, &buf_ssl);

		if (ret == 0) {
			PLUGIN_TRACE("No data needs to be written on fd %d.",
					socket_fd);
			conn->need_write = 0;
			done = 1;
			break;
		}
		else if (ret == PS_ARG_FAIL) {
			mk_err("[liana_ssl] Bad argument for GetOutdata.");
			should_close = 1;
			done = 1;
			break;
		}

		mk_api->socket_cork_flag(conn->socket_fd, MK_TRUE);
		len = ret;
		bytes_sent = write(conn->socket_fd, buf_ssl, len);
		mk_api->socket_cork_flag(conn->socket_fd, MK_FALSE);

		if (bytes_sent == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return MK_PLUGIN_RET_EVENT_CONTINUE;
			}
			mk_err("[liana_ssl] Socket error on fd %d: %s",
					socket_fd, strerror(errno));
			should_close = 1;
			done = 1;
			break;
		}

		ret = matrixSslSentData(conn->ssl, bytes_sent);

		switch (ret) {
		case MATRIXSSL_REQUEST_CLOSE:
			PLUGIN_TRACE("[FD %d] SSL socket request close.",
					conn->socket_fd);
			conn->need_write = 0;
			should_close = 1;
			break;

		case MATRIXSSL_REQUEST_SEND:
			PLUGIN_TRACE("[FD %d] SSL socket request send.",
					conn->socket_fd);
			break;

		case MATRIXSSL_HANDSHAKE_COMPLETE:
			PLUGIN_TRACE("[FD %d] SSL handshake complete.",
					conn->socket_fd);
			conn->handshake_complete = 1;

			mk_api->event_socket_change_mode(conn->socket_fd,
					MK_EPOLL_READ,
					MK_EPOLL_LEVEL_TRIGGERED);
			done = 1;
			break;

		case MATRIXSSL_SUCCESS:
			PLUGIN_TRACE("[FD %d] SSL output successfully sent.",
					conn->socket_fd);
			conn->need_write = 0;
			if (!conn->handshake_complete) {
				mk_api->event_socket_change_mode(socket_fd,
						MK_EPOLL_READ,
						MK_EPOLL_LEVEL_TRIGGERED);
			}
			done = 1;
			break;

		default:
			mk_warn("[liana_ssl][FD %d] Unknown error.",
					conn->socket_fd);
			break;
		}
	} while (!done);

	if (should_close) {
		return MK_PLUGIN_RET_EVENT_CLOSE;
	}
	else if (!conn->handshake_complete) {
		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else if (conn->try_false_start) {
		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
}

int hangup(int socket_fd)
{
	struct mk_liana_ssl *conn = liana_ssl_get_connection(socket_fd);

	if (!conn) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}

	liana_ssl_close(conn);

	matrixSslDeleteSession(conn->ssl);

	mk_list_del(&conn->cons);
	free(conn);

	return MK_PLUGIN_RET_EVENT_NEXT;
}

int _mkp_event_close(int socket_fd)
{
	PLUGIN_TRACE("[FD %d] Event close.", socket_fd);
	return hangup(socket_fd);
}

int _mkp_event_timeout(int socket_fd)
{
	PLUGIN_TRACE ("[FD %d] Event timeout", socket_fd);
	return hangup(socket_fd);
}

int _mkp_event_error(int socket_fd)
{
	PLUGIN_TRACE ("[FD %d] Event error", socket_fd);
	return hangup(socket_fd);
}
