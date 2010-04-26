# Copyright (C) 2008-2009, Eduardo Silva <edsiper@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import socket
import epoll

class Listener:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._reset_socket()

        try:
            self.s.bind(("", port))
        except:
            print "\nError: I cannot bind port", port
            exit(1)

        self.s.listen(20)
        self.sfd = self.s.fileno()

    def _reset_socket(self):
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)

