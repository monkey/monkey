cimport monkey

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

    def prin(self):
        print 'Hi'
