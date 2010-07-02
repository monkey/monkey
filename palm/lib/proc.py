# Copyright (C) 2008-2010, Eduardo Silva <edsiper@gmail.com>
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

import os
import sys
import signal
import time

from child import Child
from listener import Listener
from config import PalmConfig
from debug import *

VERSION = 0.2

class BigPalm:
    def __init__(self):
        self.print_info()

        # Read Palm configuration
        self.conf = PalmConfig()
        self.conf.readconf("conf/palm.conf")

        signal.signal(signal.SIGINT, self._on_sigint_cb)
        self._palms = {}

        # Load Palms
        self.create_palms()

    def _on_sigint_cb(self, frame, a):
        for p in self._palms:
            os.kill(self._palms[p], signal.SIGKILL)

        exit(0)

    def print_info(self):
        print "Monkey Palm Server", VERSION
        print "Visit us: http://www.monkey-project.com"

    def create_palms(self):
        for h in self.conf.get_handlers():
            # Handler configuration
            try:
                port = int(self.conf.get(h, 'Port'))
            except:
                self.conf_error(h, 'Port')

            try:            
                childs = int(self.conf.get(h, 'Childs'))
            except:
                self.conf_error(h, 'Childs')

            try:
                bin = self.conf.get(h, 'Exec')
            except:
                bin = None

            try:
                opts = self.conf.get(h, 'Arguments')
            except:
                opts = None

            # Debug Message
            debug("[+] Handler [%s] running on port %i, %i childs" % (h, port, childs))

            # Creating Palm under process context
            pid = os.fork()
            if pid:
                self._palms[h] = pid
            else:
                p = Palm(h, port, bin, opts)
                p.create_n_childs(childs)
                while 1:
                    time.sleep(1)

        while 1:
            time.sleep(1)

    def conf_error(self, h, var):
        print "\nPalm config error, no option '%s' in handler '%s'" % (var, h)
        exit(1) 

class Palm:
    _childs = []

    def __init__(self, name, port, bin, opts):
        self.name = name
        self.port = port
        self.bin = bin
        self.opts = opts

        self.listen = Listener(port)
        self.s = self.listen.s

    def create_n_childs(self, n):
        for i in range(n):
            self.create_child()

    def create_child(self):
        child = Child(self.name, self.s, self)
        self._register_child(child)

    def _register_child(self, child):
        self._childs.append(child)

    def get_child_list(self):
        return self._childs

    def get_childs_len(self):
        return len(self._childs)
    
    def kill_childs(self):
        for c in self._childs:
            c.kill()

