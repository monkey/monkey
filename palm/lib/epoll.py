from ctypes import *

# Linux sys/epoll.h values
EPOLLIN = 0x001
EPOLLPRI = 0x002
EPOLLOUT = 0x004
EPOLLRDNORM = 0x040
EPOLLRDBAND = 0x080
EPOLLWRNORM = 0x100
EPOLLWRBAND = 0x200
EPOLLMSG = 0x400
EPOLLERR = 0x008
EPOLLHUP = 0x010
EPOLLRDHUP = 0x2000
EPOLLONESHOT = (1 << 30)
EPOLLET = (1 << 31)

EPOLL_CTL_ADD = 1 
EPOLL_CTL_DEL = 2
EPOLL_CTL_MOD = 3 

# epoll data structures
class epoll_data(Structure):
    _fields_ = [("ptr", c_void_p),
                ("fd", c_int),
                ("u32", c_uint32),
                ("u64", c_uint64)]

class epoll_event(Structure):
    _fields_ = [("events", c_uint32),
                ("data", epoll_data)]

# Main class
class EPoll(object):
    _LIBC = "libc.so.6"

    def __init__(self):
        try:
            self._lib = cdll.LoadLibrary(self._LIBC)
        except:
            print "Cannot open %s" % self._LIBC
            exit(1)

    def epoll_create(self, size):
        try:
            n = self._lib.epoll_create(size)
            return n
        except:
            print "Error calling epoll_create()"
            exit(1)

    def epoll_wait(self, efd, events, max_events, timeout):
        return self._lib.epoll_wait(efd, events, max_events, timeout)


    def epoll_ctl(self, epfd, op, fd, event):
        return self._lib.epoll_ctl(epfd, op, fd, byref(event))

    def epoll_event(self, events, edata):
        return byref(epoll_event(events, edata))

