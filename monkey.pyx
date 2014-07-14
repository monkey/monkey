cimport monkey

class Mimetype:
    def __init__(self):
        self.name = ''
        self.type = ''

cdef 

cdef class Server:
    cdef monkey.mklib_ctx _server
    def __cinit__(self, address, int port, int plugins, documentroot):
        if address is None:
            if documentroot is None:
                self._server = monkey.mklib_init(NULL, port, plugins, NULL)
            else:
                self._server = monkey.mklib_init(NULL, port, plugins, documentroot)
        else:
            if documentroot is None:
                self._server = monkey.mklib_init(address, port, plugins, NULL)
            else:
                self._server = monkey.mklib_init(address, port, plugins, documentroot)

    def start(self):
        return monkey.mklib_start(self._server)

    def stop(self):
        return monkey.mklib_stop(self._server)

    def configure(self, **args):
        cdef:
            int integer, ret = 0
            char *string
        for a in args:
            if a == 'workers':
                integer = args['workers']
                ret |= mklib_config(self._server, MKC_WORKERS, integer, NULL)
            elif a == 'timeout':
                integer = args['timeout']
                ret |= mklib_config(self._server, MKC_TIMEOUT, integer, NULL)
            elif a == 'userdir':
                string = args['userdir']
                ret |= mklib_config(self._server, MKC_USERDIR, string, NULL)
            elif a == 'indexfile':
                string = args['indexfile']
                ret |= mklib_config(self._server, MKC_INDEXFILE, string, NULL)
            elif a == 'hideversion':
                integer = args['hideversion']
                ret |= mklib_config(self._server, MKC_HIDEVERSION, integer, NULL)
            elif a == 'resume':
                integer = args['resume']
                ret |= mklib_config(self._server, MKC_RESUME, integer, NULL)
            elif a == 'keepalive':
                integer = args['keepalive']
                ret |= mklib_config(self._server, MKC_KEEPALIVE, integer, NULL)
            elif a == 'keepalive_timeout':
                integer = args['keepalive_timeout']
                ret |= mklib_config(self._server, MKC_KEEPALIVETIMEOUT, integer, NULL)
            elif a == 'max_keepalive_request':
                integer = args['max_keepalive_request']
                ret |= mklib_config(self._server, MKC_MAXKEEPALIVEREQUEST, integer, NULL)
            elif a == 'max_request_size':
                integer = args['max_request_size']
                ret |= mklib_config(self._server, MKC_MAXREQUESTSIZE, integer, NULL)
            elif a == 'symlink':
                integer = args['symlink']
                ret |= mklib_config(self._server, MKC_SYMLINK, integer, NULL)
            elif a == 'default_mimetype':
                string = args['default_mimetype']
                ret |= mklib_config(self._server, MKC_DEFAULTMIMETYPE, string, NULL)
        return ret

    def getconfig(self):
        cdef:
            int workers, timeout, resume, keepalive, keepalive_timeout, max_keepalive_request, max_request_size, symlink
            char userdir[1024], default_mimetype[1024]
        ret = {}
        monkey.mklib_get_config(self._server, MKC_WORKERS, &workers, MKC_TIMEOUT, &timeout, MKC_USERDIR, userdir, MKC_RESUME, &resume, MKC_KEEPALIVE, &keepalive, MKC_KEEPALIVETIMEOUT, &keepalive_timeout, MKC_MAXKEEPALIVEREQUEST, &max_keepalive_request, MKC_MAXREQUESTSIZE, &max_request_size, MKC_SYMLINK, &symlink, MKC_DEFAULTMIMETYPE, default_mimetype, NULL)
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

    def mimetype_list(self):
        cdef:
            mklib_mime **mimetypes
            int i = 0
        ret = []
        mimetypes = mklib_mimetype_list(self._server)
        while mimetypes[i] != NULL:
            if mimetypes[i] == NULL:
                break
            mimetype = Mimetype()
            mimetype.name = mimetypes[i].name
            mimetype.type = mimetypes[i].type
            ret.append(mimetype)
            i += 1
        return ret

    def mimetype_add(self, char *name, char *type):
        return mklib_mimetype_add(self._server, name, type)

    cdef c_set_callback(self, mklib_cb cb, void *f):
        return mklib_callback_set(self._server, cb, <void *> f)

    def set_callback(self, cb, f):
        if cb == 'data':
            return mklib_callback_set(self._server, MKCB_DATA, <void *> f)
        if cb == 'ip':
            return self.c_set_callback(MKCB_IPCHECK, <void *> f)
        if cb == 'url':
            return self.c_set_callback(MKCB_URLCHECK, <void *> f)
        if cb == 'close':
            return self.c_set_callback(MKCB_CLOSE, <void *> f)
