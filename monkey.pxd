cdef extern from "libmonkey.h":
    ctypedef struct mklib_ctx_t:
        pass
    ctypedef mklib_ctx_t *mklib_ctx
    ctypedef void mklib_session

    mklib_ctx mklib_init(char *address, unsigned int port, unsigned int plugins, char *documentroot)
    int mklib_start(mklib_ctx)
    int mklib_stop(mklib_ctx)
    int mklib_config(mklib_ctx, ...)
