/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P.
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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "MKPlugin.h"

#include "auth.h"
#include "conf.h"
#include "sha1/sha1.h"
#include "base64/base64.h"

MONKEY_PLUGIN("auth",              /* shortname */
              "Authentication",    /* name */ 
              VERSION,             /* version */
              MK_PLUGIN_STAGE_30); /* hooks */

struct mk_config *conf;

struct users_file *mk_auth_load_users(char *path)
{
    int i, sep, len;
    int offset = 0;
    size_t decoded_len;
    char *buf;
    struct user *cred;
    struct users_file  *uf;
    struct file_info *finfo=NULL;

    mk_api->file_get_info(path, finfo);
    if (!finfo) {
        mk_warn("Cannot open users file '%s'", path);
        return NULL;
    }

    if (finfo->is_directory == MK_TRUE || finfo->read_access == MK_FALSE) {
        mk_warn("Cannot read users file '%s'", path);
        return NULL;
    }

    buf = mk_api->file_to_buffer(path);
    if (!buf) {
        mk_warn("Cannot read users file '%s'", path);
        return NULL;
    }

    uf = mk_api->mem_alloc(sizeof(struct users_file));
    mk_list_init(&uf->_head);

    /* Read users list buffer lines */
    len = strlen(buf);
    for (i = 0; i < len; i++) {
        if (buf[i] == '\n' || (i) == len -1) {
            sep = mk_api->str_search(buf + offset, ":", 1);
            cred = mk_api->mem_alloc(sizeof(struct user));

            /* Copy username */
            strncpy(cred->user, buf + offset, offset + sep);
            cred->user[sep] = '\0';

            /* Copy raw password */
            offset += sep + 1 + 5;
            strncpy(cred->passwd_raw,
                    buf + offset,
                    i - (offset));
            cred->passwd_raw[i - offset] = '\0';

            /* Decode raw password */
            cred->passwd_decoded = base64_decode((unsigned char *)(cred->passwd_raw),
                                                 strlen(cred->passwd_raw),
                                                 &decoded_len);
            //cred->passwd_decoded[decoded_len] = '\0';
            
            mk_info("**\n   user     : '%s'\n   p_raw    : '%s'", 
                    cred->user, cred->passwd_raw);
            offset = i + 1;

            mk_list_add(&cred->_head, &uf->_head);
        }
    }

    mk_api->mem_free(buf);
    return uf;
}

int mk_auth_validate_user(struct session_request *sr,
                          const char *credentials, unsigned int len)
{
    int sep;
    size_t auth_len;
    size_t decoded_len;
    unsigned char *decoded;
    unsigned char digest[SHA1_DIGEST_LEN];
    struct mk_list *head;
    struct users *entry;
    struct vhost *vh_entry;

    SHA_CTX sha; /* defined in sha1/sha1.h */

    /* Validate value length */
    if (len <= auth_header_basic.len + 1) {
        return -1;
    }

    /* Validate 'basic' credential type */
    if (strncmp(credentials, auth_header_basic.data, 
                auth_header_basic.len) != 0) {
        return -1;
    }

    /* Decode credentials */
    decoded = base64_decode((unsigned char *) credentials + auth_header_basic.len,
                            len - auth_header_basic.len,
                            &auth_len);
    decoded[auth_len] = '\0';

    if (auth_len <= 3) {
        return -1;
    }

    mk_info("Decoded: '%s' len=%i", decoded, auth_len);

    sep = mk_api->str_search_n((char *) decoded, ":", 1, auth_len);
    if (sep == -1 || sep == 0  || sep == auth_len - 1) {
        return -1;
    }
    
    /* Match sr->vhost with auth_vhost */
    mk_list_foreach(head, &vhosts_list) {
        vh_entry = mk_list_entry(head, struct vhost, _head);
        if (vh_entry->host == sr->host_conf) {
            break;
        }
    }

    return -1;

    /*
    if (strncmp((char *) decoded, "eduardo", sep - 1) != 0) {
        mk_warn("invalid user");
        return -1;
    }

    if (strncmp((char *) decoded + sep + 1, "pass", 4) != 0) {
        mk_warn("invalid pass");
        return -1;
    }
    */

    /* Get SHA1 hash */
    SHA1_Init(&sha);
    SHA1_Update(&sha, (unsigned char *) decoded + sep + 1, 4);
    SHA1_Final(digest, &sha);

    mk_info("\nrebase64: '%s'", base64_encode((unsigned char *) digest, 20, &decoded_len));

    /*
    mk_list_foreach(head, &users_list) {
        entry = mk_list_entry(head, struct users, _head);
        if (memcmp(entry->passwd_decoded, digest, 20) == 0) {
            mk_warn("not equal");
        }
        printf("\n->entry: '%s'", entry->user);
        fflush(stdout);
    }
    */

    return 0;
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;

    /* Init and load global users list */
    mk_list_init(&vhosts_list);
    mk_list_init(&users_file_list);
    mk_auth_conf_init_users_list();
    //mk_auth_load_users("");
  
    /* Set HTTP headers key */
    auth_header_request.data = MK_AUTH_HEADER_REQUEST;
    auth_header_request.len  = sizeof(MK_AUTH_HEADER_REQUEST) - 1;

    auth_header_basic.data = MK_AUTH_HEADER_BASIC;
    auth_header_basic.len  = sizeof(MK_AUTH_HEADER_BASIC) - 1;

    return 0;
}

void _mkp_exit()
{
}

void _mkp_core_thctx()
{
    char *user;

    /* Init thread buffer for given credentials */
    user = mk_api->mem_alloc(MK_AUTH_CREDENTIALS_LEN - 1);
    pthread_setspecific(_mkp_data, (void *) user);    
}

/* Object handler */
int _mkp_stage_30(struct plugin *plugin, 
                  struct client_session *cs, 
                  struct session_request *sr)
{
    int val;
    mk_pointer res;

    /* Check authorization header */
    res = mk_api->header_get(&sr->headers_toc, auth_header_request);
    if (res.data && res.len > 0) {
        /* Validate user */
        val = mk_auth_validate_user(sr, res.data, res.len);
        if (val == 0) {
            /* user validated, success */
            return MK_PLUGIN_RET_NOT_ME;
        }
    }

    /* Restrict access: failed user */
    sr->headers.content_length = 0;
    mk_api->header_set_http_status(sr, MK_CLIENT_UNAUTH);
    mk_api->header_add(sr,
                       "WWW-Authenticate: Basic realm=\"Monkey Auth Plugin\"",
                       50);
    mk_api->header_send(cs->socket, cs, sr);

    return MK_PLUGIN_RET_END;
}
