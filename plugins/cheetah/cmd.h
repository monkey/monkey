time_t init_time;

/* commands */
void mk_cheetah_cmd(char *cmd);

void mk_cheetah_cmd_clear();
void mk_cheetah_cmd_uptime();

/* Plugins commands */
void mk_cheetah_cmd_plugins_print_stage(struct plugin *list, const char *stage, 
                                        int stage_bw);
void mk_cheetah_cmd_plugins_print_core(struct plugin *list);
void mk_cheetah_cmd_plugins_print_network(struct plugin *list);
void mk_cheetah_cmd_plugins();

void mk_cheetah_cmd_vhosts();
void mk_cheetah_cmd_workers();

void mk_cheetah_cmd_quit();
void mk_cheetah_cmd_help();
void mk_cheetah_cmd_config();
void mk_cheetah_cmd_status();

