/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2012, Lauri Kasanen
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

#include <sys/time.h>
#include <sys/resource.h>

#include "cgi.h"

MONKEY_PLUGIN("cgi",		/* shortname */
              "CGI handler",	/* name */
              VERSION,		/* version */
              MK_PLUGIN_STAGE_30 | MK_PLUGIN_CORE_THCTX);	/* hooks */

static regex_t match_regex;

struct cgi_request **requests_by_socket;

struct post_t {
    int fd;
    void *buf;
    unsigned long len;
};

int swrite(const int fd, const void *buf, const size_t count)
{
    ssize_t pos = count, ret = 0;

    while (pos > 0 && ret >= 0) {
        ret = write(fd, buf, pos);
        pos -= ret;
        buf += ret;
    }

    if (ret < 0)
        return 0;

    return 1;
}

static void cgi_write_post(void *p)
{
    const struct post_t * const in = p;

    swrite(in->fd, in->buf, in->len);
    close(in->fd);
}

static int do_cgi(const char * const __restrict__ file, const char * const __restrict__ url,
                  struct session_request * const sr,
                  struct client_session * const cs,
                  struct plugin * const plugin)
{
    const int socket = cs->socket;

    char *env[30];

    /* Unchanging env vars */
    env[0] = "PATH_INFO=";
    env[1] = "GATEWAY_INTERFACE=CGI/1.1";
    env[2] = "REDIRECT_STATUS=200";
    const int env_start = 3;

    /* Dynamic env vars */

    unsigned short envpos = env_start;

    char method[SHORTLEN];
    char *query = NULL;
    char request_uri[PATHLEN];
    char script_filename[PATHLEN];
    char script_name[PATHLEN];
    char query_string[PATHLEN];
    char remote_addr[INET6_ADDRSTRLEN+SHORTLEN];
    char tmpaddr[INET6_ADDRSTRLEN], *ptr = tmpaddr;
    char remote_port[SHORTLEN];
    char content_length[SHORTLEN];
    char content_type[SHORTLEN];
    char server_software[SHORTLEN];
    char server_protocol[SHORTLEN];
    char http_host[SHORTLEN];

    snprintf(method, SHORTLEN, "REQUEST_METHOD=%s", sr->method_p.data);
    env[envpos++] = method;

    snprintf(server_software, SHORTLEN, "SERVER_SOFTWARE=%s", sr->host_conf->host_signature);
    env[envpos++] = server_software;

    snprintf(http_host, SHORTLEN, "HTTP_HOST=%.*s", (int) sr->host.len, sr->host.data);
    env[envpos++] = http_host;

    char *protocol;
    if (sr->protocol == HTTP_PROTOCOL_11)
        protocol = HTTP_PROTOCOL_11_STR;
    else
        protocol = HTTP_PROTOCOL_10_STR;

    snprintf(server_protocol, SHORTLEN, "SERVER_PROTOCOL=%s", protocol);
    env[envpos++] = server_protocol;

    if (sr->query_string.len) {
        query = mk_api->mem_alloc_z(sr->query_string.len + 1);
        memcpy(query, sr->query_string.data, sr->query_string.len);
        snprintf(request_uri, PATHLEN, "REQUEST_URI=%s?%s", url, query);
    }
    else {
        snprintf(request_uri, PATHLEN, "REQUEST_URI=%s", url);
    }
    env[envpos++] = request_uri;

    snprintf(script_filename, PATHLEN, "SCRIPT_FILENAME=%s", file);
    env[envpos++] = script_filename;

    snprintf(script_name, PATHLEN, "SCRIPT_NAME=%s", url);
    env[envpos++] = script_name;

    if (query) {
        snprintf(query_string, PATHLEN, "QUERY_STRING=%s", query);
        env[envpos++] = query_string;
        free(query);
    }

    unsigned long len;
    if (mk_api->socket_ip_str(socket, &ptr, INET6_ADDRSTRLEN, &len) < 0)
        tmpaddr[0] = '\0';
    snprintf(remote_addr, INET6_ADDRSTRLEN+SHORTLEN, "REMOTE_ADDR=%s", tmpaddr);
    env[envpos++] = remote_addr;

    snprintf(remote_port, SHORTLEN, "REMOTE_PORT=%ld", sr->port);
    env[envpos++] = remote_port;

    if (sr->data.len) {
        snprintf(content_length, SHORTLEN, "CONTENT_LENGTH=%lu", sr->data.len);
        env[envpos++] = content_length;
    }

    if (sr->content_type.len) {
        snprintf(content_type, SHORTLEN, "CONTENT_TYPE=%s", sr->content_type.data);
        env[envpos++] = content_type;
    }


    /* Must be NULL-terminated */
    env[envpos] = NULL;

    /* pipes, from monkey's POV */
    int writepipe[2], readpipe[2];
    if (pipe(writepipe) || pipe(readpipe)) {
        mk_err("Failed to create pipe");
        return 403;
    }

    pid_t pid = vfork();
    if (pid < 0) {
        mk_err("Failed to fork");
        return 403;
    }

    /* Child */
    if (pid == 0) {
        close(writepipe[1]);
        close(readpipe[0]);

        /* Our stdin is the read end of monkey's writing */
        if (dup2(writepipe[0], 0) < 0) {
            mk_err("dup2 failed");
            _exit(1);
        }
        close(writepipe[0]);

        /* Our stdout is the write end of monkey's reading */
        if (dup2(readpipe[1], 1) < 0) {
            mk_err("dup2 failed");
            _exit(1);
        }
        close(readpipe[1]);

        char *argv[2] = { NULL };

        char *tmp = strdup(file);
        chdir(dirname(tmp));

        char *tmp2 = strdup(file);
        argv[0] = basename(tmp2);

        /* Restore signals for the child */
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        execve(file, argv, env);

        /* Exec failed, return */
        _exit(1);
    }

    /* Yay me */
    close(writepipe[0]);
    close(readpipe[1]);

    /* If we have POST data to write, spawn a thread to do that */
    if (sr->data.len) {
        struct post_t p;
        p.fd = writepipe[1];
        p.buf = sr->data.data;
        p.len = sr->data.len;

        mk_api->worker_spawn(cgi_write_post, &p);
    }
    else {
        close(writepipe[1]);
    }


    struct cgi_request *r = cgi_req_create(readpipe[0], socket);
    if (!r) return 403;

    cgi_req_add(r);
    mk_api->event_add(readpipe[0], MK_EPOLL_READ, plugin, cs, sr, MK_EPOLL_LEVEL_TRIGGERED);

    /* XXX Fixme: this needs to be atomic */
    requests_by_socket[socket] = r;

    /* We have nothing to write yet */
    mk_api->event_socket_change_mode(socket, MK_EPOLL_READ, MK_EPOLL_LEVEL_TRIGGERED);

    return 200;
}

static void cgi_read_config(const char * const path)
{
    char *file = NULL;
    unsigned long len;
    struct mk_config *conf;
    struct mk_config_section *section;

    mk_api->str_build(&file, &len, "%scgi.conf", path);
    conf = mk_api->config_create(file);
    section = mk_api->config_section_get(conf, "CGI");

    if (section) {
        char *match = mk_api->config_section_getval(section, "Match", MK_CONFIG_VAL_STR);
        if (match) {
//            printf("Got match %s\n", match);

            char *p = match;
            while (*p) {
                if (*p == ' ') *p = '|';
                p++;
            }

//            printf("Got match %s\n", match);
            int ret = regcomp(&match_regex, match, REG_EXTENDED|REG_ICASE|REG_NOSUB);
            if (ret) {
                char tmp[80];
                regerror(ret, &match_regex, tmp, 80);
                mk_err("CGI: Failed to compile regex: %s", tmp);
            }

            free(match);
        }
    }

    free(file);
    mk_api->config_free(conf);
}

int _mkp_init(struct plugin_api **api, char *confdir)
{
    mk_api = *api;
    cgi_read_config(confdir);

    pthread_key_create(&_mkp_data, NULL);

    struct rlimit lim;
    getrlimit(RLIMIT_NOFILE, &lim);
//    printf("Allocating a cache for %lu fds\n", lim.rlim_cur);
    requests_by_socket = mk_api->mem_alloc_z(sizeof(struct cgi_request *) * lim.rlim_cur);

    /* Make sure we act good if the child dies */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    return 0;
}

void _mkp_exit()
{
    regfree(&match_regex);
    free(requests_by_socket);
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
                  struct session_request *sr)
{
    char url[PATHLEN];
    if (sr->uri.len + 1 > PATHLEN)
        return MK_PLUGIN_RET_NOT_ME;

    memcpy(url, sr->uri.data, sr->uri.len);
    url[sr->uri.len] = '\0';

//    printf("Got URL %s\n", url);
//    printf("Realpath: %s\n", sr->real_path.data);

    const char * const file = sr->real_path.data;

    if (!sr->file_info.is_file || !sr->file_info.exec_access)
        return MK_PLUGIN_RET_NOT_ME;

    if (regexec(&match_regex, url, 0, NULL, 0))
        return MK_PLUGIN_RET_NOT_ME;

    if (cgi_req_get(cs->socket)) {
        printf("Error, someone tried to retry\n");
        return MK_PLUGIN_RET_CONTINUE;
    }

    int status = do_cgi(file, url, sr, cs, plugin);

    /* These are just for the other plugins, such as logger; bogus data */
    mk_api->header_set_http_status(sr, status);

    if (status != 200)
        return MK_PLUGIN_RET_END;

    sr->close_now = MK_TRUE;

    return MK_PLUGIN_RET_CONTINUE;
}

void _mkp_core_thctx()
{
    struct mk_list *list = mk_api->mem_alloc_z(sizeof(struct mk_list));

    mk_list_init(list);
    pthread_setspecific(_mkp_data, list);
}
