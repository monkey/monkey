char **MOD_Read_Config(char *mod_name);
char *MOD_get_ptr_value(char **ptr, char *var);

/* mod_mysql: Defs */

int mod_mysql_init();
int mod_mysql_log_main(struct request *sr);

/* end mod_mysql */
