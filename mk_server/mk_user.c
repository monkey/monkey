/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/monkey.h>
#include <monkey/mk_user.h>
#include <monkey/mk_http.h>
#include <monkey/mk_http_status.h>
#include <monkey/mk_core.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_config.h>

#include <pwd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <grp.h>

int mk_user_init(struct mk_http_session *cs, struct mk_http_request *sr)
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

    memcpy(user, sr->uri_processed.data + offset, limit);
    user[limit] = '\0';

    MK_TRACE("user: '%s'", user);

    /* Check system user */
    if ((s_user = getpwnam(user)) == NULL) {
        mk_http_error(MK_CLIENT_NOT_FOUND, cs, sr);
        return -1;
    }

    if (sr->uri_processed.len > (unsigned int) (offset+limit)) {
        user_uri = mk_mem_alloc(sr->uri_processed.len);
        if (!user_uri) {
            return -1;
        }

        memcpy(user_uri,
               sr->uri_processed.data + (offset + limit),
               sr->uri_processed.len - offset - limit);
        user_uri[sr->uri_processed.len - offset - limit] = '\0';

        mk_string_build(&sr->real_path.data, &sr->real_path.len,
                        "%s/%s%s",
                        s_user->pw_dir, mk_config->conf_user_pub, user_uri);
        mk_mem_free(user_uri);
    }
    else {
        mk_string_build(&sr->real_path.data, &sr->real_path.len,
                        "%s/%s", s_user->pw_dir, mk_config->conf_user_pub);
    }

    sr->user_home = MK_TRUE;
    return 0;
}

/* Change process user */
int mk_user_set_uidgid()
{
    struct passwd *usr;

    /* Launched by root ? */
    if (geteuid() == 0 && mk_config->user) {
        struct rlimit rl;

        if (getrlimit(RLIMIT_NOFILE, &rl)) {
            mk_warn("cannot get resource limits");
        }

        /* Check if user exists  */
        if ((usr = getpwnam(mk_config->user)) == NULL) {
            mk_err("Invalid user '%s'", mk_config->user);
            goto out;
        }

        if (initgroups(mk_config->user, usr->pw_gid) != 0) {
            mk_err("Initgroups() failed");
        }

        /* Change process UID and GID */
        if (setegid(usr->pw_gid) == -1) {
            mk_err("I cannot change the GID to %u", usr->pw_gid);
        }

        if (seteuid(usr->pw_uid) == -1) {
            mk_err("I cannot change the UID to %u", usr->pw_uid);
        }

        mk_config->is_seteuid = MK_TRUE;
    }

    out:

    /* Variables set for run checks on file permission */
    EUID = geteuid();
    EGID = getegid();

    return 0;
}

static int cmpgid_t(const void *p1, const void *p2){
	return (int)*((gid_t*)p1) - (int)*((gid_t*)p2);
}

/* Get the group list from the user */
int mk_user_get_groups()
{
    mk_user_groups.length=getgroups(0,NULL);
    mk_user_groups.array=calloc(mk_user_groups.length, sizeof(gid_t));
    if(mk_user_groups.array == NULL) {
        mk_err("Allocation failure");
        return -1;
    }
    if(getgroups(mk_user_groups.length, mk_user_groups.array)<0) {
        mk_err("I couldn't get the usergroups");
        return -1;
    }
    qsort(mk_user_groups.array, mk_user_groups.length, sizeof(gid_t), 
        &cmpgid_t);
    return 0;
}

/* Perform a binary search with O(log n). 
 * Returns 1 when found, 0 otherwise 
 */
int mk_group_in_grouplist(gid_t group)
{
    ssize_t a=0,b=mk_user_groups.length-1, i=0;
    while(a<=b){
        i=(a+b)/2;
        if(group<mk_user_groups.array[i]){
            b=i-1;
        }
        else if(group>mk_user_groups.array[i]){
            a=i+1;
        }
        else{
            return 1; //Group found;
        }
    }
    return 0; //Group not found;
}

/* Checks wether the executing user is inside the given group */
int mk_user_in_group(gid_t group){
    return (group == EGID || mk_group_in_grouplist(group));
}

/* Return process to the original user */
int mk_user_undo_uidgid()
{
    if (mk_config->is_seteuid == MK_TRUE) {
        if (setegid(0) < 0) {
            mk_err("Can't restore effective GID");
        }
        if (seteuid(0) < 0) {
            mk_err("Can't restore effective UID");
        }
    }
    return 0;
}
