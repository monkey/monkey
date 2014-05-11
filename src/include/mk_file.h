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

#include <sys/types.h>

#ifndef MK_FILE_H
#define MK_FILE_H

struct file_info
{
    off_t size;
    time_t last_modification;

    /* Suggest flags to open this file */
    int flags_read_only;

    unsigned char exists;
    unsigned char is_file;
    unsigned char is_link;
    unsigned char is_directory;
    unsigned char exec_access;
    unsigned char read_access;
};

int mk_file_get_info(const char *path, struct file_info *f_info);
char *mk_file_to_buffer(const char *path);

#endif
