
import socket
import epoll

class Listener:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._reset_socket()
        self.s.bind(("", port))
        self.s.listen(20)
        self.sfd = self.s.fileno()

    def _reset_socket(self):
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)

