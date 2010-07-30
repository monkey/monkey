#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

#include "MKPlugin.h"

#include "cheetah.h"
#include "cmd.h"

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

    while ((n = mk_api->str_search(buf + last, " ")) > 0) {
        if (c == 23) {
            value = mk_api->str_copy_substr(buf, init, last + n);
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

    printf("%s[%s]%s", ANSI_BOLD ANSI_YELLOW, stage, ANSI_RESET);
  
    while (p) {
       if (p->hooks & stage_bw) {
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

    printf("\n%s[CORE PROCESS CONTEXT]%s", ANSI_BOLD ANSI_BLUE, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_CORE_PRCTX) {
            printf("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    printf("\n");
    p = list;
    printf("\n%s[CORE THREAD CONTEXT]%s", ANSI_BOLD ANSI_BLUE, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_CORE_THCTX) {
            printf("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    printf("\n\n");
}

void mk_cheetah_cmd_plugins_print_network(struct plugin *list)
{
    struct plugin *p;

    p = list;

    printf("%s[NETWORK I/O]%s", ANSI_BOLD ANSI_RED, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_NETWORK_IO) {
            printf("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    p = list;
    printf("\n\n%s[NETWORK IP]%s", ANSI_BOLD ANSI_RED, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_NETWORK_IP) {
            printf("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    printf("\n");
}

void mk_cheetah_cmd_plugins()
{
    struct plugin *list = mk_api->plugins;

    printf("List of plugins and hooks associated\n");

    if (!list) {
        return;
    }

    mk_cheetah_cmd_plugins_print_core(list);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_10", MK_PLUGIN_STAGE_10);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_20", MK_PLUGIN_STAGE_20);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_30", MK_PLUGIN_STAGE_30);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_40", MK_PLUGIN_STAGE_40);
    mk_cheetah_cmd_plugins_print_stage(list, "STAGE_50", MK_PLUGIN_STAGE_50);
    mk_cheetah_cmd_plugins_print_network(list);

    printf("\n");
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
    printf("\nconfig     (\\f)    Display global configuration");
    printf("\nplugins    (\\g)    List loaded plugins and associated stages");
    printf("\nstatus     (\\s)    Display general web server information");
    printf("\nuptime     (\\u)    Display how long the web server has been running");
    printf("\nvhosts     (\\v)    List virtual hosts configured");
    printf("\nworkers    (\\w)    Show thread workers information\n");
    printf("\nclear      (\\c)    Clear screen");
    printf("\nhelp       (\\h)    Print this help");
    printf("\nquit       (\\q)    Exit Cheetah shell :_(\n\n");
}

void mk_cheetah_cmd_config()
{
    struct mk_string_line *line;

    printf("Basic configuration");
    printf("\n-------------------");
    printf("\nServer Port     : %i", mk_api->config->serverport);
    
    if (strcmp(mk_api->config->listen_addr, "0.0.0.0") == 0) {
        printf("\nListen          : All interfaces");
    }
    else {
        printf("\nListen          : %s", mk_api->config->listen_addr);
    }
    printf("\nWorkers         : %i threads", mk_api->config->workers);
    printf("\nTimeout         : %i seconds", mk_api->config->timeout);
    printf("\nPidFile         : %s", mk_api->config->pid_file_path);
    printf("\nUserDir         : %s", mk_api->config->user_dir);

    line = mk_api->config->index_files;
    if (!line) {
        printf("\nIndexFile       : No index files defined");
    }
    else {
        printf("\nIndexFile       : ");
        while (line) {
            printf("%s ", line->val);
            line = line->next;
        }

    }
    
    printf("\nHideVersion     : ");
    if (mk_api->config->hideversion == VAR_ON) {
        printf("On");
    }
    else {
        printf("Off");
    }

    printf("\nResume          : ");
    if (mk_api->config->resume == VAR_ON) {
        printf("On");
    }
    else {
        printf("Off");
    }

    printf("\nUser            : %s", mk_api->config->user);
    printf("\n\nAdvanced configuration");
    printf("\n----------------------");
    printf("\nKeepAlive           : ");
    if (mk_api->config->keep_alive == VAR_ON) {
        printf("On");
    }
    else {
        printf("Off");
    }
    printf("\nMaxKeepAliveRequest : %i req/connection", 
           mk_api->config->max_keep_alive_request); 
    printf("\nKeepAliveTimeout    : %i seconds", mk_api->config->keep_alive_timeout);
    printf("\nMaxRequestSize      : %i KB", 
           mk_api->config->max_request_size/1024);
    printf("\nSymLink             : ");
    if (mk_api->config->symlink == VAR_ON) {
        printf("On");
    }
    else {
        printf("Off");
    }
    printf("\n\n");
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
