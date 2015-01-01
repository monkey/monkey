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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <limits.h>

#ifdef LINUX_TRACE
#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE
#include <monkey/mk_linuxtrace.h>
#endif

#include <monkey/monkey.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_user.h>
#include <monkey/mk_signals.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_cache.h>
#include <monkey/mk_server.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_env.h>
#include <monkey/mk_http.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_config.h>
#include <monkey/mk_scheduler.h>

#if defined(__DATE__) && defined(__TIME__)
static const char MONKEY_BUILT[] = __DATE__ " " __TIME__;
#else
static const char MONKEY_BUILT[] = "Unknown";
#endif

const mk_ptr_t mk_monkey_protocol = mk_ptr_init(MK_HTTP_PROTOCOL_11_STR);

void mk_thread_keys_init(void)
{
    /* Create thread keys */
    pthread_key_create(&mk_utils_error_key, NULL);
}

#ifndef SHAREDLIB
static void mk_version(void)
{
    printf("Monkey HTTP Server v%i.%i.%i\n",
           __MONKEY__, __MONKEY_MINOR__, __MONKEY_PATCHLEVEL__);
    printf("Built : %s (%s %i.%i.%i)\n",
           MONKEY_BUILT, CC, __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    printf("Home  : http://monkey-project.com\n");
    fflush(stdout);
}

static void mk_build_info(void)
{
    mk_version();

    printf("\n");
    printf("%s[system: %s]%s\n", ANSI_BOLD, OS, ANSI_RESET);
    printf("%s", MK_BUILD_UNAME);

    printf("\n\n%s[configure]%s\n", ANSI_BOLD, ANSI_RESET);
    printf("%s", MK_BUILD_CMD);

    printf("\n\n%s[setup]%s\n", ANSI_BOLD, ANSI_RESET);
    printf("configuration dir: %s\n", MONKEY_PATH_CONF);
    printf("\n\n");
}

static void mk_help(int rc)
{
    printf("Usage : monkey [-c directory] [-p TCP_PORT ] [-w N] [-D] [-v] [-h]\n\n");
    printf("%sAvailable options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -c, --configdir=DIR\t\t\tspecify configuration files directory\n");
    printf("  -s, --serverconf=FILE\t\t\tspecify main server configuration file\n");
    printf("  -D, --daemon\t\t\t\trun Monkey as daemon (background mode)\n");
    printf("  -p, --port=PORT\t\t\tset listener TCP port (override config)\n");
    printf("  -o, --one-shot=DIR\t\t\tone-shot, serve a single directory\n");
    printf("  -t, --transport=TRANSPORT\t\tspecify transport layer (override config)\n");
    printf("  -w, --workers=N\t\t\tset number of workers (override config)\n");
    printf("  -m, --mimes-conf-file=FILE\t\tspecify mimes configuration file\n");
    printf("  -l, --plugins-load-conf-file=FILE\tspecify plugins.load configuration file\n");
    printf("  -S, --sites-conf-dir=dir\t\tspecify sites configuration directory\n");
    printf("  -P, --plugins-conf-dir=dir\t\tspecify plugin configuration directory\n\n");

    printf("%sInformational%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -b, --build\t\t\tprint build information\n");
    printf("  -v, --version\t\t\tshow version number\n");
    printf("  -h, --help\t\t\tprint this help\n\n");

    printf("%sDocumentation%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  http://monkey-project.com/documentation\n\n");

    exit(rc);
}

/* MAIN */
int main(int argc, char **argv)
{
    int opt;
    char *port_override = NULL;
    int workers_override = -1;
    int run_daemon = 0;
    char *one_shot = NULL;
    char *transport_layer = NULL;
    char *path_config = NULL;
    char *server_conf_file = NULL;
    char *plugin_load_conf_file = NULL;
    char *sites_conf_dir = NULL;
    char *plugins_conf_dir = NULL;
    char *mimes_conf_file = NULL;

    static const struct option long_opts[] = {
        { "configdir",              required_argument,  NULL, 'c' },
        { "serverconf",             required_argument,  NULL, 's' },
        { "build",                  no_argument,        NULL, 'b' },
        { "daemon",                 no_argument,        NULL, 'D' },
        { "port",                   required_argument,  NULL, 'p' },
        { "one-shot",               required_argument,  NULL, 'o' },
        { "transport",              required_argument,  NULL, 't' },
        { "workers",                required_argument,  NULL, 'w' },
        { "version",                no_argument,        NULL, 'v' },
        { "help",                   no_argument,        NULL, 'h' },
        { "mimes-conf-file",        required_argument,  NULL, 'm' },
        { "plugin-load-conf-file",  required_argument,  NULL, 'l' },
        { "plugins-conf-dir",       required_argument,  NULL, 'P' },
        { "sites-conf-dir",         required_argument,  NULL, 'S' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "bDSvhp:o:t:w:c:s:m:l:P:S:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'b':
            mk_build_info();
            exit(EXIT_SUCCESS);
        case 'v':
            mk_version();
            exit(EXIT_SUCCESS);
        case 'h':
            mk_help(EXIT_SUCCESS);
        case 'D':
            run_daemon = 1;
            break;
        case 'p':
            port_override = optarg;
            break;
        case 'o':
            one_shot = optarg;
            break;
        case 't':
            transport_layer = mk_string_dup(optarg);
            break;
        case 'w':
            workers_override = atoi(optarg);
            break;
        case 'c':
            path_config = optarg;
            break;
        case 's':
            server_conf_file = optarg;
            break;
        case 'm':
            mimes_conf_file = optarg;
            break;
        case 'P':
            plugins_conf_dir = optarg;
            break;
        case 'S':
            sites_conf_dir = optarg;
            break;
        case 'l':
            plugin_load_conf_file = optarg;
            break;
        case '?':
            mk_help(EXIT_FAILURE);
        }
    }

    /* setup basic configurations */
    config = mk_config_init();

    /* Init Kernel version data */
    mk_kernel_init();
    mk_kernel_features();

    /* set configuration path */
    if (!path_config) {
        config->path_config = MONKEY_PATH_CONF;
    }
    else {
        config->path_config = path_config;
    }

    /* set target configuration file for the server */
    if (!server_conf_file) {
        config->server_conf_file = MK_DEFAULT_CONFIG_FILE;
    }
    else {
        config->server_conf_file = server_conf_file;
    }

    if (run_daemon) {
        config->is_daemon = MK_TRUE;
    }
    else {
        config->is_daemon = MK_FALSE;
    }

    if (!mimes_conf_file) {
        config->mimes_conf_file = MK_DEFAULT_MIMES_CONF_FILE;
    }
    else {
        config->mimes_conf_file = mimes_conf_file;
    }

    if (!plugin_load_conf_file) {
        config->plugin_load_conf_file = MK_DEFAULT_PLUGIN_LOAD_CONF_FILE;
    }
    else {
        config->plugin_load_conf_file = plugin_load_conf_file;
    }

    if (!sites_conf_dir) {
        config->sites_conf_dir = MK_DEFAULT_SITES_CONF_DIR;
    }
    else {
        config->sites_conf_dir = sites_conf_dir;
    }

    if (!plugins_conf_dir) {
        config->plugins_conf_dir = MK_DEFAULT_PLUGINS_CONF_DIR;
    }
    else {
        config->plugins_conf_dir = plugins_conf_dir;
    }

    /* Override some configuration */
    config->one_shot = one_shot;
    config->port_override = port_override;
    config->transport_layer = transport_layer;

#ifdef TRACE
    monkey_init_time = time(NULL);
    MK_TRACE("Monkey TRACE is enabled");
    env_trace_filter = getenv("MK_TRACE_FILTER");
    pthread_mutex_init(&mutex_trace, (pthread_mutexattr_t *) NULL);
#endif
    pthread_mutex_init(&mutex_port_init, (pthread_mutexattr_t *) NULL);

    mk_version();
    mk_signal_init();

#ifdef LINUX_TRACE
    mk_info("Linux Trace enabled");
#endif

    /* Override number of thread workers */
    if (workers_override >= 0) {
        config->workers = workers_override;
    }
    else {
        config->workers = -1;
    }

    /* Core and Scheduler setup */
    mk_config_start_configure();
    mk_sched_init();

    /* Clock init that must happen before starting threads */
    mk_clock_sequential_init();

    /* Load plugins */
    mk_plugin_api_init();
    mk_plugin_load_all();

    /* Running Monkey as daemon */
    if (config->is_daemon == MK_TRUE) {
        mk_utils_set_daemon();
    }

    /* Register PID of Monkey */
    mk_utils_register_pid();

    /* Workers: logger and clock */
    mk_clock_tid = mk_utils_worker_spawn((void *) mk_clock_worker_init, NULL);

    /* Init mk pointers */
    mk_mem_pointers_init();

    /* Init thread keys */
    mk_thread_keys_init();

    /* Configuration sanity check */
    mk_config_sanity_check();

    /* Invoke Plugin PRCTX hooks */
    mk_plugin_core_process();

    /* Launch monkey http workers */
    mk_server_launch_workers();

    /* Print server details */
    mk_details();

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

    /* Change process owner */
    mk_user_set_uidgid();

    /* Server loop, let's listen for incomming clients */
    mk_server_loop();

    mk_mem_free(config);
    return 0;
}
#endif
