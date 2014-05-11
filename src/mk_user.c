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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <grp.h>

#include "monkey.h"
#include "mk_user.h"
#include "mk_http.h"
#include "mk_http_status.h"
#include "mk_memory.h"
#include "mk_string.h"
#include "mk_utils.h"
#include "mk_config.h"
#include "mk_macros.h"

int mk_user_init(struct client_session *cs, struct session_request *sr)
{
    int limit;
    const int offset = 2; /* The user is defined after the '/~' string, so offset = 2 */
    const int user_len = 255;
    char user[user_len], *user_uri;
    struct passwd *s_user;

    if (sr->uri_processed.len <= 2) {
        return -1;
    }

    limit = mk_string_char_search(sr->uri_processed.data + offset, '/',
                                  sr->uri_processed.len);

    if (limit == -1) {
        limit = (sr->uri_processed.len) - offset;
    }

    if (limit + offset >= (user_len)) {
        return -1;
    }

    strncpy(user, sr->uri_processed.data + offset, limit);
    user[limit] = '\0';

    MK_TRACE("user: '%s'", user);

    /* Check system user */
    if ((s_user = getpwnam(user)) == NULL) {
        mk_request_error(MK_CLIENT_NOT_FOUND, cs, sr);
        return -1;
    }

    if (sr->uri_processed.len > (unsigned int) (offset+limit)) {
        user_uri = mk_mem_malloc(sr->uri_processed.len);
        if (!user_uri) {
            return -1;
        }

        strncpy(user_uri,
                sr->uri_processed.data + (offset + limit),
                sr->uri_processed.len - offset - limit);
        user_uri[sr->uri_processed.len - offset - limit] = '\0';

        mk_string_build(&sr->real_path.data, &sr->real_path.len,
                        "%s/%s%s", s_user->pw_dir, config->user_dir, user_uri);
        mk_mem_free(user_uri);
    }
    else {
        mk_string_build(&sr->real_path.data, &sr->real_path.len,
                        "%s/%s", s_user->pw_dir, config->user_dir);
    }

    sr->user_home = MK_TRUE;
    return 0;
}

#ifndef SHAREDLIB

/* Change process user */
int mk_user_set_uidgid()
{
    struct passwd *usr;

    /* Launched by root ? */
    if (geteuid() == 0 && config->user) {
        struct rlimit rl;

        if (getrlimit(RLIMIT_NOFILE, &rl)) {
            mk_warn("cannot get resource limits");
        }

        /* Just if i'm superuser */
        rl.rlim_cur = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            mk_warn("cannot set resource limits");
        }

        /* Check if user exists  */
        if ((usr = getpwnam(config->user)) == NULL) {
            mk_err("Invalid user '%s'", config->user);
            goto out;
        }

        if (initgroups(config->user, usr->pw_gid) != 0) {
            mk_err("Initgroups() failed");
        }

        /* Change process UID and GID */
        if (setgid(usr->pw_gid) == -1) {
            mk_err("I cannot change the GID to %u", usr->pw_gid);
        }

        if (setuid(usr->pw_uid) == -1) {
            mk_err("I cannot change the UID to %u", usr->pw_uid);
        }

        config->is_seteuid = MK_TRUE;
    }

    out:
    EUID = geteuid();
    EGID = getegid();

    return 0;
}

/* Return process to the original user */
int mk_user_undo_uidgid()
{
    if (config->is_seteuid == MK_TRUE) {
        if (setegid(0) < 0) mk_err("Can't restore effective GID");
        if (seteuid(0) < 0) mk_err("Can't restore effective UID");
    }
    return 0;
}

#endif // !SHAREDLIB
