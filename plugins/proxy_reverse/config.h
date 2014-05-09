/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *  Copyright (C) 2013, Nikola Nikov
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

//TODO some of the structures are using C99

enum balancer_type
{
    Naive = 1,
    FirstAlive,
    SourceHash,
    RoundRobin,
    LockingRoundRobin,
    LeastConnections,
    /*Hash=1,
       FirstAlive,
       RoundRobin,
       WRoundRobin */
};

struct proxy_server_entry
{
    char *hostname;
    int port;
};

struct proxy_server_entry_array
{
    unsigned int length;
    struct proxy_server_entry entry[];
};

struct match_regex_array
{
    unsigned int length;
    regex_t entry[];
};

struct proxy_cnf_default_values
{
    int count;
    int timeout;
    char *stats_url;
    struct proxy_server_entry_array *server_list;
    enum balancer_type balancer_type;
};

struct proxy_entry
{
    struct proxy_server_entry_array *server_list;
    enum balancer_type balancer_type;
    struct match_regex_array *regex_array;
    int count;
    int timeout;
    char *stats_url;            // May be to make better structure, and not to make stats_url for every entry
};

struct proxy_entry_array
{
    unsigned int length;
    struct proxy_entry entry[];
};

struct proxy_entry_array *proxy_reverse_read_config(const char *);

struct proxy_entry *proxy_check_match(char *, struct proxy_entry_array *);
