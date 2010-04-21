/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P.
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
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

#include "monkey.h"
#include "config.h"
#include "scheduler.h"
#include "info.h"
#include "request.h"
#include "str.h"
#include "plugin.h"
#include "worker.h"

#include "cheetah.h"

#define MK_CHEETAH_CLEAR "clear"
#define MK_CHEETAH_CLEAR_SC "\\c"

#define MK_CHEETAH_STATUS "status"
#define MK_CHEETAH_STATUS_SC "\\s"

#define MK_CHEETAH_HELP "help"
#define MK_CHEETAH_HELP_SC "\\h"

#define MK_CHEETAH_SHELP "?"
#define MK_CHEETAH_SHELP_SC "\\?"

#define MK_CHEETAH_UPTIME "uptime"
#define MK_CHEETAH_UPTIME_SC "\\u"

#define MK_CHEETAH_PLUGINS "plugins"
#define MK_CHEETAH_PLUGINS_SC "\\g"

#define MK_CHEETAH_VHOSTS "vhosts"
#define MK_CHEETAH_VHOSTS_SC "\\v"

#define MK_CHEETAH_WORKERS "workers"
#define MK_CHEETAH_WORKERS_SC "\\w"

#define MK_CHEETAH_QUIT "quit"
#define MK_CHEETAH_QUIT_SC "\\q"

#define MK_CHEETAH_PROMPT "%s%scheetah>%s "
#define MK_CHEETAH_PROC_TASK "/proc/%i/task/%i/stat"
#define MK_CHEETAH_ONEDAY  86400
#define MK_CHEETAH_ONEHOUR  3600
#define MK_CHEETAH_ONEMINUTE  60

/* Plugin data for register */
mk_plugin_data_t _shortname = "cheetah";
mk_plugin_data_t _name = "Cheetah";
mk_plugin_data_t _version = "1.1";
mk_plugin_hook_t _hooks = MK_PLUGIN_STAGE_10;

time_t init_time;
struct plugin_api *mk_api;

void mk_cheetah_print_worker_memory_usage(pid_t pid)
{
    int last, init, n, c = 0;
    int s = 1024;
    char *buf;
    char *value;
    pid_t ppid;
    FILE *f;

    ppid = getpid();
    buf = mk_api->mem_alloc(s);
    sprintf(buf, MK_CHEETAH_PROC_TASK, ppid, pid);

    f = fopen(buf, "r");
    if (!f) {
        printf("Cannot get details\n");
        return;
    }

    buf = fgets(buf, s, f);
    if (!buf) {
        printf("Cannot format details\n");
        return;
    }
    fclose(f);

    last = 0;
    init = 0;

    printf("\n");
    return;

    while ((n = mk_string_search(buf + last, " ")) > 0) {
        if (c == 23) {
            value = mk_string_copy_substr(buf, init, last + n);
            printf("%s\n", value);
            mk_mem_free(buf);
            mk_mem_free(value);
            return;
        }
        init = last + n + 1;
        last += n + 1;
        c++;
    }
}

void mk_cheetah_print_running_user()
{
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    size_t bufsize;
    uid_t uid;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }

    buf = malloc(bufsize);
    uid = getuid();
    getpwuid_r(uid, &pwd, buf, bufsize, &result);

    printf("%s\n", pwd.pw_name);
    free(buf);
}

void mk_cheetah_cmd_clear()
{
    printf("\033[2J\033[1;1H");
}

void mk_cheetah_cmd_uptime()
{
    int days;
    int hours;
    int minutes;
    int seconds;
    long int upmind;
    long int upminh;
    long int uptime;

    /* uptime in seconds */
    uptime = time(NULL) - init_time;

    /* days */
    days = uptime / MK_CHEETAH_ONEDAY;
    upmind = uptime - (days * MK_CHEETAH_ONEDAY);

    /* hours */
    hours = upmind / MK_CHEETAH_ONEHOUR;
    upminh = upmind - hours * MK_CHEETAH_ONEHOUR;

    /* minutes */
    minutes = upminh / MK_CHEETAH_ONEMINUTE;
    seconds = upminh - minutes * MK_CHEETAH_ONEMINUTE;

    printf
        ("Server has been running: %i day%s, %i hour%s, %i minute%s and %i second%s\n\n",
         days, (days > 1) ? "s" : "", hours, (hours > 1) ? "s" : "", minutes,
         (minutes > 1) ? "s" : "", seconds, (seconds > 1) ? "s" : "");
}

void mk_cheetah_cmd_plugins_print_stage(struct plugin *list, const char *stage, 
                                        int stage_bw)
{
    struct plugin *p;

    if (!list) {
        return;
    }

    p = list;

    printf("[%s]", stage);
  
    while (p) {
        if (*p->hooks & stage_bw) {
            printf("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    printf("\n\n");
}

void mk_cheetah_cmd_plugins_print_core(struct plugin *list)
{
    struct plugin *p;

    p = list;

    while (p) {
        printf("\n[CORE PROCESS CONTEXT]");
        if (*p->hooks & MK_PLUGIN_CORE_PRCTX) {
            printf("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    printf("\n\n");
}

void mk_cheetah_cmd_plugins()
{
    struct plugin *list = mk_api->plugins;

    printf("List of plugins loaded and stages associated\n\n");

    if (!list) {
        return;
    }

    mk_cheetah_cmd_plugins_print_core(list);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_10", MK_PLUGIN_STAGE_10);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_20", MK_PLUGIN_STAGE_20);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_30", MK_PLUGIN_STAGE_30);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_40", MK_PLUGIN_STAGE_40);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_50", MK_PLUGIN_STAGE_50);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_60", MK_PLUGIN_STAGE_60);
}

void mk_cheetah_cmd_vhosts()
{
    struct host *host;

    host = mk_api->config->hosts;

    while (host) {
        printf("* VHost '%s'\n", host->servername);
        printf("      - Configuration Path     : %s\n", host->file);
        printf("      - Document Root          : %s\n",
               host->documentroot.data);
        printf("      - Access Log             : %s\n",
               host->access_log_path);
        printf("      - Error Log              : %s\n", host->error_log_path);
        host = host->next;
    }

    printf("\n");
}

void mk_cheetah_cmd_workers()
{
    struct sched_list_node *sl;
    sl = *mk_api->sched_list;

    while (sl) {
        printf("* Worker %i\n", sl->idx);
        printf("      - Task ID           : %i\n", sl->pid);

        /* Memory Usage 
        printf("      - Memory usage      : ");
        mk_cheetah_print_worker_memory_usage(sl->pid);

        
        printf("      - Active Requests   : %i\n", sl->active_requests);
        printf("      - Closed Requests   : %i\n", sl->closed_requests);
        */
        
        sl = sl->next;
    }

    printf("\n");
}

void mk_cheetah_cmd_quit()
{
    printf("Cheeta says: Good Bye!\n");
    fflush(stdout);
    pthread_exit(NULL);
}

void mk_cheetah_cmd_help()
{
    printf("List of available commands for Cheetah Shell\n");
    printf("\ncommand  shortcut  description");
    printf("\n----------------------------------------------------");
    printf("\n?          (\\?)    Synonym for 'help'");
    printf("\nplugins    (\\g)    List loaded plugins and associated stages");
    printf("\nstatus     (\\s)    Display general web server information");
    printf("\nuptime     (\\u)    Display how long the web server has been running");
    printf("\nvhosts     (\\v)    List virtual hosts configured");
    printf("\nworkers    (\\w)    Show thread workers information\n");
    printf("\nclear      (\\c)    Clear screen");
    printf("\nhelp       (\\h)    Print this help");
    printf("\nquit       (\\q)    Exit Cheetah shell :_(\n\n");
}

void mk_cheetah_cmd_status()
{
    int nthreads = 0;

    struct sched_list_node *sl;


    sl = *mk_api->sched_list;
    while (sl) {
        nthreads++;
        sl = sl->next;
    }

    printf("Cheetah Plugin v%s\n\n", _version);
    printf("Monkey Version     : %s\n", VERSION);
    printf("Configutarion path : %s\n", mk_api->config->serverconf);
    printf("Process ID         : %i\n", getpid());
    printf("Process User       : ");
    mk_cheetah_print_running_user();

    printf("Server Port        : %i\n", mk_api->config->serverport);
    printf("Worker Threads     : %i (per configuration: %i)\n\n",
           nthreads, mk_api->config->workers);

}

void mk_cheetah_cmd(char *cmd)
{
    if (strcmp(cmd, MK_CHEETAH_STATUS) == 0 ||
        strcmp(cmd, MK_CHEETAH_STATUS_SC) == 0) {
        mk_cheetah_cmd_status();
    }
    else if (strcmp(cmd, MK_CHEETAH_CLEAR) == 0 ||
             strcmp(cmd, MK_CHEETAH_CLEAR_SC) == 0) {
        mk_cheetah_cmd_clear();
    }
    else if (strcmp(cmd, MK_CHEETAH_UPTIME) == 0 ||
             strcmp(cmd, MK_CHEETAH_UPTIME_SC) == 0) {
        mk_cheetah_cmd_uptime();
    }
    else if (strcmp(cmd, MK_CHEETAH_PLUGINS) == 0 ||
             strcmp(cmd, MK_CHEETAH_PLUGINS_SC) == 0) {
        mk_cheetah_cmd_plugins();
    }
    else if (strcmp(cmd, MK_CHEETAH_WORKERS) == 0 ||
             strcmp(cmd, MK_CHEETAH_WORKERS_SC) == 0) {
        mk_cheetah_cmd_workers();
    }
    else if (strcmp(cmd, MK_CHEETAH_VHOSTS) == 0 ||
             strcmp(cmd, MK_CHEETAH_VHOSTS_SC) == 0) {
        mk_cheetah_cmd_vhosts();
    }
    else if (strcmp(cmd, MK_CHEETAH_HELP) == 0 ||
             strcmp(cmd, MK_CHEETAH_HELP_SC) == 0 ||
             strcmp(cmd, MK_CHEETAH_SHELP) == 0 ||
             strcmp(cmd, MK_CHEETAH_SHELP_SC) == 0) {
        mk_cheetah_cmd_help();
    }
    else if (strcmp(cmd, MK_CHEETAH_QUIT) == 0 ||
             strcmp(cmd, MK_CHEETAH_QUIT_SC) == 0) {
        mk_cheetah_cmd_quit();
    }
    else if (strlen(cmd) == 0) {
        return;
    }
    else {
        printf("Invalid command, type 'help' for a list of available commands\n");
    }

    fflush(stdout);
}

void mk_cheetah_loop()
{
    int len;
    char cmd[200];
    char line[200];
    char *rcmd;

    printf("\n%s%s***%s Welcome to %sCheetah!%s, the %sMonkey Shell %s:) %s***%s\n",
           ANSI_BOLD, ANSI_YELLOW,
           ANSI_WHITE, ANSI_GREEN, 
           ANSI_WHITE, ANSI_RED, ANSI_WHITE, ANSI_YELLOW, ANSI_RESET);
    printf("\n      << %sType 'help' or '\\h' for help%s >>\n\n",
           ANSI_BLUE, ANSI_RESET);
    fflush(stdout);

    while (1) {
        printf(MK_CHEETAH_PROMPT, ANSI_BOLD, ANSI_GREEN, ANSI_RESET);
        rcmd = fgets(line, sizeof(line), stdin);

        len = strlen(line);
        
        if (len == 0){
            printf("\n");
            mk_cheetah_cmd_quit();
        }

        strncpy(cmd, line, len - 1);
        cmd[len - 1] = '\0';

        mk_cheetah_cmd(cmd);
        bzero(line, sizeof(line));
    }
}

void *mk_cheetah_init(void *args)
{
    init_time = time(NULL);
    mk_cheetah_loop();
    return 0;
}

/* This function is called when the plugin is loaded, it must
 * return 
 */
int _mkp_init(void **api)
{
    mk_api = *api;
    return 0;
}

int _mkp_stage_10(struct server_config *config)
{
    pthread_t tid;
    pthread_attr_t thread_attr;

    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &thread_attr, (void *) mk_cheetah_init, config) <
        0) {
        perror("pthread_create");
        exit(1);
    }

    return 0;
}
