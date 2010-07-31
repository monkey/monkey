#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

#include "MKPlugin.h"

#include "cheetah.h"
#include "cutils.h"
#include "cmd.h"

void mk_cheetah_cmd(char *cmd)
{
    if (strcmp(cmd, MK_CHEETAH_CONFIG) == 0 ||
        strcmp(cmd, MK_CHEETAH_CONFIG_SC) == 0) {
        mk_cheetah_cmd_config();
    }
    else if (strcmp(cmd, MK_CHEETAH_STATUS) == 0 ||
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

    CHEETAH_WRITE("%s[%s]%s", ANSI_BOLD ANSI_YELLOW, stage, ANSI_RESET);
  
    while (p) {
       if (p->hooks & stage_bw) {
            CHEETAH_WRITE("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    CHEETAH_WRITE("\n\n");
}

void mk_cheetah_cmd_plugins_print_core(struct plugin *list)
{
    struct plugin *p;

    p = list;

    CHEETAH_WRITE("\n%s[CORE PROCESS CONTEXT]%s", ANSI_BOLD ANSI_BLUE, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_CORE_PRCTX) {
            CHEETAH_WRITE("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    CHEETAH_WRITE("\n");
    p = list;
    CHEETAH_WRITE("\n%s[CORE THREAD CONTEXT]%s", ANSI_BOLD ANSI_BLUE, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_CORE_THCTX) {
            CHEETAH_WRITE("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    CHEETAH_WRITE("\n\n");
}

void mk_cheetah_cmd_plugins_print_network(struct plugin *list)
{
    struct plugin *p;

    p = list;

    CHEETAH_WRITE("%s[NETWORK I/O]%s", ANSI_BOLD ANSI_RED, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_NETWORK_IO) {
            CHEETAH_WRITE("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    p = list;
    CHEETAH_WRITE("\n\n%s[NETWORK IP]%s", ANSI_BOLD ANSI_RED, ANSI_RESET);

    while (p) {
        if (p->hooks & MK_PLUGIN_NETWORK_IP) {
            CHEETAH_WRITE("\n  [%s] %s v%s on \"%s\"",
                   p->shortname, p->name, p->version, p->path);
        }
        p = p->next;
    }

    CHEETAH_WRITE("\n");
}

void mk_cheetah_cmd_plugins()
{
    struct plugin *list = mk_api->plugins;

    CHEETAH_WRITE("List of plugins and hooks associated\n");

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

    CHEETAH_WRITE("\n");
}

void mk_cheetah_cmd_vhosts()
{
    struct host *host;

    host = mk_api->config->hosts;

    while (host) {
        CHEETAH_WRITE("* VHost '%s'\n", host->servername);
        CHEETAH_WRITE("      - Configuration Path     : %s\n", host->file);
        CHEETAH_WRITE("      - Document Root          : %s\n",
               host->documentroot.data);
        CHEETAH_WRITE("      - Access Log             : %s\n",
               host->access_log_path);
        CHEETAH_WRITE("      - Error Log              : %s\n", host->error_log_path);
        host = host->next;
    }

    CHEETAH_WRITE("\n");
}

void mk_cheetah_cmd_workers()
{
    struct sched_list_node *sl;
    sl = *mk_api->sched_list;

    while (sl) {
        CHEETAH_WRITE("* Worker %i\n", sl->idx);
        CHEETAH_WRITE("      - Task ID           : %i\n", sl->pid);

        /* Memory Usage 
        CHEETAH_WRITE("      - Memory usage      : ");
        mk_cheetah_print_worker_memory_usage(sl->pid);

        
        CHEETAH_WRITE("      - Active Requests   : %i\n", sl->active_requests);
        CHEETAH_WRITE("      - Closed Requests   : %i\n", sl->closed_requests);
        */
        
        sl = sl->next;
    }

    CHEETAH_WRITE("\n");
}

void mk_cheetah_cmd_quit()
{
    CHEETAH_WRITE("Cheeta says: Good Bye!\n");
    fflush(stdout);
    pthread_exit(NULL);
}

void mk_cheetah_cmd_help()
{
    CHEETAH_WRITE("List of available commands for Cheetah Shell\n");
    CHEETAH_WRITE("\ncommand  shortcut  description");
    CHEETAH_WRITE("\n----------------------------------------------------");
    CHEETAH_WRITE("\n?          (\\?)    Synonym for 'help'");
    CHEETAH_WRITE("\nconfig     (\\f)    Display global configuration");
    CHEETAH_WRITE("\nplugins    (\\g)    List loaded plugins and associated stages");
    CHEETAH_WRITE("\nstatus     (\\s)    Display general web server information");
    CHEETAH_WRITE("\nuptime     (\\u)    Display how long the web server has been running");
    CHEETAH_WRITE("\nvhosts     (\\v)    List virtual hosts configured");
    CHEETAH_WRITE("\nworkers    (\\w)    Show thread workers information\n");
    CHEETAH_WRITE("\nclear      (\\c)    Clear screen");
    CHEETAH_WRITE("\nhelp       (\\h)    Print this help");
    CHEETAH_WRITE("\nquit       (\\q)    Exit Cheetah shell :_(\n\n");
}

void mk_cheetah_cmd_config()
{
    struct mk_string_line *line;

    CHEETAH_WRITE("Basic configuration");
    CHEETAH_WRITE("\n-------------------");
    CHEETAH_WRITE("\nServer Port     : %i", mk_api->config->serverport);
    
    if (strcmp(mk_api->config->listen_addr, "0.0.0.0") == 0) {
        CHEETAH_WRITE("\nListen          : All interfaces");
    }
    else {
        CHEETAH_WRITE("\nListen          : %s", mk_api->config->listen_addr);
    }
    CHEETAH_WRITE("\nWorkers         : %i threads", mk_api->config->workers);
    CHEETAH_WRITE("\nTimeout         : %i seconds", mk_api->config->timeout);
    CHEETAH_WRITE("\nPidFile         : %s", mk_api->config->pid_file_path);
    CHEETAH_WRITE("\nUserDir         : %s", mk_api->config->user_dir);

    line = mk_api->config->index_files;
    if (!line) {
        CHEETAH_WRITE("\nIndexFile       : No index files defined");
    }
    else {
        CHEETAH_WRITE("\nIndexFile       : ");
        while (line) {
            CHEETAH_WRITE("%s ", line->val);
            line = line->next;
        }

    }
    
    CHEETAH_WRITE("\nHideVersion     : ");
    if (mk_api->config->hideversion == VAR_ON) {
        CHEETAH_WRITE("On");
    }
    else {
        CHEETAH_WRITE("Off");
    }

    CHEETAH_WRITE("\nResume          : ");
    if (mk_api->config->resume == VAR_ON) {
        CHEETAH_WRITE("On");
    }
    else {
        CHEETAH_WRITE("Off");
    }

    CHEETAH_WRITE("\nUser            : %s", mk_api->config->user);
    CHEETAH_WRITE("\n\nAdvanced configuration");
    CHEETAH_WRITE("\n----------------------");
    CHEETAH_WRITE("\nKeepAlive           : ");
    if (mk_api->config->keep_alive == VAR_ON) {
        CHEETAH_WRITE("On");
    }
    else {
        CHEETAH_WRITE("Off");
    }
    CHEETAH_WRITE("\nMaxKeepAliveRequest : %i req/connection", 
           mk_api->config->max_keep_alive_request); 
    CHEETAH_WRITE("\nKeepAliveTimeout    : %i seconds", mk_api->config->keep_alive_timeout);
    CHEETAH_WRITE("\nMaxRequestSize      : %i KB", 
           mk_api->config->max_request_size/1024);
    CHEETAH_WRITE("\nSymLink             : ");
    if (mk_api->config->symlink == VAR_ON) {
        CHEETAH_WRITE("On");
    }
    else {
        CHEETAH_WRITE("Off");
    }
    CHEETAH_WRITE("\n\n");
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

    /* FIXME */
    //CHEETAH_WRITE("Cheetah Plugin v%s\n\n", _plugin_info->version);
    CHEETAH_WRITE("Monkey Version     : %s\n", VERSION);
    CHEETAH_WRITE("Configutarion path : %s\n", mk_api->config->serverconf);
    CHEETAH_WRITE("Process ID         : %i\n", getpid());
    CHEETAH_WRITE("Process User       : ");
    mk_cheetah_print_running_user();

    CHEETAH_WRITE("Server Port        : %i\n", mk_api->config->serverport);
    CHEETAH_WRITE("Worker Threads     : %i (per configuration: %i)\n\n",
           nthreads, mk_api->config->workers);

}


