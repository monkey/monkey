#include <monkey/mk_plugin.h>

struct mk_plugin mk_plugin_liana;

void mk_static_plugins()
{
    struct mk_plugin *p;

    p = &mk_plugin_liana;
    mk_list_add(&p->_head, mk_config->plugins);

}
