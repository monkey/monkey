/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>

#include "monkey.h"
#include "mk_socket.h"
#include "mk_user.h"
#include "mk_signals.h"
#include "mk_clock.h"
#include "mk_cache.h"
#include "mk_server.h"
#include "mk_plugin.h"
#include "mk_macros.h"
#include "mk_env.h"
#include "mk_http.h"

#if defined(__DATE__) && defined(__TIME__)
static const char MONKEY_BUILT[] = __DATE__ " " __TIME__;
#else
static const char MONKEY_BUILT[] = "Unknown";
#endif

const mk_pointer mk_monkey_protocol = mk_pointer_init(HTTP_PROTOCOL_11_STR);
gid_t EGID;
gid_t EUID;

void mk_thread_keys_init(void)
{
    /* Create thread keys */
    pthread_key_create(&worker_sched_node, NULL);
    pthread_key_create(&request_list, NULL);
    pthread_key_create(&mk_epoll_state_k, NULL);
    pthread_key_create(&mk_cache_iov_header, NULL);
    pthread_key_create(&mk_cache_header_lm, NULL);
    pthread_key_create(&mk_cache_header_cl, NULL);
    pthread_key_create(&mk_cache_header_ka, NULL);
    pthread_key_create(&mk_cache_header_ka_max, NULL);
    pthread_key_create(&mk_cache_utils_gmtime, NULL);
    pthread_key_create(&mk_cache_utils_gmt_text, NULL);
    pthread_key_create(&mk_plugin_event_k, NULL);
}

#ifndef SHAREDLIB
static void mk_details(void)
{
    printf("* Process ID is %i", getpid());
    printf("\n* Server socket listening on Port %i", config->serverport);
    printf("\n* %i threads, %i client connections per thread, total %i",
           config->workers, config->worker_capacity,
           config->workers * config->worker_capacity);
    printf("\n* Transport layer by %s in %s mode\n",
           config->transport_layer_plugin->shortname,
           config->transport);
    fflush(stdout);
}

static void mk_version(void)
{
    printf("Monkey HTTP Daemon %i.%i.%i\n",
           __MONKEY__, __MONKEY_MINOR__, __MONKEY_PATCHLEVEL__);
    printf("Built : %s (%s %i.%i.%i)\n",
           MONKEY_BUILT, CC, __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    printf("Home  : http://monkey-project.com\n");
    fflush(stdout);
}

static void mk_help(int rc)
{
    printf("Usage : monkey [-c directory] [-D] [-v] [-h]\n\n");
    printf("%sAvailable options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -c, --confdir=DIR\tspecify configuration files directory\n");
    printf("  -D, --daemon\t\trun Monkey as daemon (background mode)\n");
    printf("  -v, --version\t\tshow version number\n");
    printf("  -h, --help\t\tprint this help\n\n");
    printf("%sDocumentation%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  http://www.monkey-project.com/documentation\n\n");

    exit(rc);
}

/* MAIN */
int main(int argc, char **argv)
{
    int opt, run_daemon = 0;
    char *file_config = NULL;

    static const struct option long_opts[] = {
        { "configdir", required_argument, NULL, 'c' },
		{ "daemon",	   no_argument,       NULL, 'D' },
        { "version",   no_argument,       NULL, 'v' },
		{ "help",	   no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

    while ((opt = getopt_long(argc, argv, "DSvhc:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'v':
            mk_version();
            exit(EXIT_SUCCESS);
        case 'h':
            mk_help(EXIT_SUCCESS);
        case 'D':
            run_daemon = 1;
            break;
        case 'c':
            file_config = optarg;
            break;
        case '?':
            printf("Monkey: Invalid option or option needs an argument.\n");
            mk_help(EXIT_FAILURE);
        }
    }

    /* setup basic configurations */
    config = mk_mem_malloc_z(sizeof(struct server_config));

    if (!file_config)
        config->file_config = MONKEY_PATH_CONF;
    else
        config->file_config = file_config;

    if (run_daemon)
        config->is_daemon = MK_TRUE;
    else
        config->is_daemon = MK_FALSE;

#ifdef TRACE
    monkey_init_time = time(NULL);
    MK_TRACE("Monkey TRACE is enabled");
    env_trace_filter = getenv("MK_TRACE_FILTER");
    pthread_mutex_init(&mutex_trace, (pthread_mutexattr_t *) NULL);
#endif

    mk_version();
    mk_signal_init();
    mk_config_start_configure();
    mk_sched_init();
    mk_plugin_init();
    mk_plugin_read_config();

    /* Server listening socket */
    config->server_fd = mk_socket_server(config->serverport, config->listen_addr);

    /* Running Monkey as daemon */
    if (config->is_daemon == MK_TRUE) {
        mk_utils_set_daemon();
    }

    /* Register PID of Monkey */
    mk_utils_register_pid();

    /* Clock init that must happen before starting threads */
    mk_clock_sequential_init();

    /* Workers: logger and clock */
    mk_utils_worker_spawn((void *) mk_clock_worker_init, NULL);

    /* Init mk pointers */
    mk_mem_pointers_init();

    /* Init thread keys */
    mk_thread_keys_init();

    /* Change process owner */
    mk_user_set_uidgid();

    /* Configuration sanity check */
    mk_config_sanity_check();

    /* Print server details */
    mk_details();

    /* Invoke Plugin PRCTX hooks */
    mk_plugin_core_process();

    /* Launch monkey http workers */
    mk_server_launch_workers();

    /* Wait until all workers report as ready */
    while (1) {
        int i, ready = 0;

        pthread_mutex_lock(&mutex_worker_init);
        for (i = 0; i < config->workers; i++) {
            if (sched_list[i].initialized)
                ready++;
        }
        pthread_mutex_unlock(&mutex_worker_init);

        if (ready == config->workers) break;
        usleep(10000);
    }

    /* Server loop, let's listen for incomming clients */
    mk_server_loop(config->server_fd);

    mk_mem_free(config);
    return 0;
}
#endif
