cimport monkey

cdef:
    void *c_cb_ipcheck_fn
    void *c_cb_data_fn
    void *c_cb_urlcheck_fn
    void *c_cb_close_fn
    monkey.mklib_ctx _server

cdef class Mimetype:
    def __init__(self):
        self.name = ''
        self.type = ''

cdef int c_cb_ipcheck(char *ip) with gil:
    func = <object> c_cb_ipcheck_fn
    return func(ip)

cdef int c_cb_urlcheck(char *ip) with gil:
    func = <object> c_cb_urlcheck_fn
    return func(ip)

cdef int c_cb_data(mklib_session *session, char *vhost, char *url, char *get, unsigned long get_len, char *post, unsigned long post_len, unsigned int *status, char **content, unsigned long *clen, char *header) with gil:
    py_vhost = None if url == NULL else vhost
    py_url = None if url == NULL else url
    py_get = None if get == NULL else get
    py_post = None if post == NULL else post
    py_header = None if header == NULL else header
    func = <object> c_cb_data_fn
    ret = func(py_vhost, py_url, py_get, get_len, py_post, post_len, py_header)
    if 'content' in ret:
        content[0] = ret['content']
    if 'status' in ret:
        status[0] = ret['status']
    if 'clen' in ret:
        clen[0] = ret['clen']
    return ret['return']

cdef int c_cb_close(mklib_session *session) with gil:
    func = <object> c_cb_close_fn
    return func()

def init(address, int port, int plugins, documentroot):
    global _server
    if address is None:
        if documentroot is None:
            _server = monkey.mklib_init(NULL, port, plugins, NULL)
        else:
            _server = monkey.mklib_init(NULL, port, plugins, documentroot)
    else:
        if documentroot is None:
            _server = monkey.mklib_init(address, port, plugins, NULL)
        else:
            _server = monkey.mklib_init(address, port, plugins, documentroot)

def start():
    return monkey.mklib_start(_server)

def stop():
    return monkey.mklib_stop(_server)

def configure(**args):
    cdef:
        int integer, ret = 0
        char *string
    for a in args:
        if a == 'workers':
            integer = args['workers']
            ret |= mklib_config(_server, MKC_WORKERS, integer, NULL)
        elif a == 'timeout':
            integer = args['timeout']
            ret |= mklib_config(_server, MKC_TIMEOUT, integer, NULL)
        elif a == 'userdir':
            string = args['userdir']
            ret |= mklib_config(_server, MKC_USERDIR, string, NULL)
        elif a == 'indexfile':
            string = args['indexfile']
            ret |= mklib_config(_server, MKC_INDEXFILE, string, NULL)
        elif a == 'hideversion':
            integer = args['hideversion']
            ret |= mklib_config(_server, MKC_HIDEVERSION, integer, NULL)
        elif a == 'resume':
            integer = args['resume']
            ret |= mklib_config(_server, MKC_RESUME, integer, NULL)
        elif a == 'keepalive':
            integer = args['keepalive']
            ret |= mklib_config(_server, MKC_KEEPALIVE, integer, NULL)
        elif a == 'keepalive_timeout':
            integer = args['keepalive_timeout']
            ret |= mklib_config(_server, MKC_KEEPALIVETIMEOUT, integer, NULL)
        elif a == 'max_keepalive_request':
            integer = args['max_keepalive_request']
            ret |= mklib_config(_server, MKC_MAXKEEPALIVEREQUEST, integer, NULL)
        elif a == 'max_request_size':
            integer = args['max_request_size']
            ret |= mklib_config(_server, MKC_MAXREQUESTSIZE, integer, NULL)
        elif a == 'symlink':
            integer = args['symlink']
            ret |= mklib_config(_server, MKC_SYMLINK, integer, NULL)
        elif a == 'default_mimetype':
            string = args['default_mimetype']
            ret |= mklib_config(_server, MKC_DEFAULTMIMETYPE, string, NULL)
    return ret

def getconfig():
    cdef:
        int workers, timeout, resume, keepalive, keepalive_timeout, max_keepalive_request, max_request_size, symlink
        char userdir[1024]
        char default_mimetype[1024]
    ret = {}
    monkey.mklib_get_config(_server, MKC_WORKERS, &workers, MKC_TIMEOUT, &timeout, MKC_USERDIR, userdir, MKC_RESUME, &resume, MKC_KEEPALIVE, &keepalive, MKC_KEEPALIVETIMEOUT, &keepalive_timeout, MKC_MAXKEEPALIVEREQUEST, &max_keepalive_request, MKC_MAXREQUESTSIZE, &max_request_size, MKC_SYMLINK, &symlink, MKC_DEFAULTMIMETYPE, default_mimetype, NULL)
    ret['workers'] = workers
    ret['timeout'] = timeout
    ret['userdir'] = userdir
    ret['resume'] = resume
    ret['keepalive'] = keepalive
    ret['keepalive_timeout'] = keepalive_timeout
    ret['max_keepalive_request'] = max_keepalive_request
    ret['max_request_size'] = max_request_size
    ret['symlink'] = symlink
    ret['default_mimetype'] = default_mimetype
    return ret

def mimetype_list():
    cdef:
        mklib_mime **mimetypes
        int i = 0
    ret = []
    mimetypes = mklib_mimetype_list(_server)
    while mimetypes[i] != NULL:
        if mimetypes[i] == NULL:
            break
        mimetype = Mimetype()
        mimetype.name = mimetypes[i].name
        mimetype.type = mimetypes[i].type
        ret.append(mimetype)
        i += 1
    return ret

def mimetype_add(char *name, char *type):
    return mklib_mimetype_add(_server, name, type)

def set_callback(cb, f):
    if cb == 'data':
        global c_cb_data_fn
        c_cb_data_fn = <void *> f
        return mklib_callback_set(_server, MKCB_DATA, <void *> c_cb_data)
    if cb == 'ip':
        global c_cb_ipcheck
        c_cb_ipcheck_fn = f
        return mklib_callback_set(_server, MKCB_IPCHECK, <void *> c_cb_ipcheck)
    if cb == 'url':
        c_cb_urlcheck_fn = f
        return mklib_callback_set(_server, MKCB_URLCHECK, <void *> c_cb_urlcheck)
    if cb == 'close':
        c_cb_close_fn = f
        return mklib_callback_set(_server, MKCB_CLOSE, <void *> c_cb_close)
