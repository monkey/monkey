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

import os
import sys
import time
import signal
from epoll import *

class Child:
    def __init__(self, s, conf):
        self._s = s
        self.conf = conf
        self.split_conf()

        # On child end, re-create it
        signal.signal(signal.SIGCHLD, self._child_exit)
        
        # Start our child
        self._create()
    
    def split_conf(self):
        try:
            opts = self.conf.opts.split()
        except:
            opts = []

        self.c = {'bin': self.conf.bin, 'opts': opts}

    def _create(self):
        # Creating pipes
        [self.ext_r, self.int_w] = os.pipe()
        [self.int_r, self.ext_w] = os.pipe()

        # Fork process
        pid = os.fork()
        if pid:
            self._pid = pid
            # Close unused pipe ends
            os.close(self.int_w)
            os.close(self.int_r)
        else:
            # Close unused pipe ends
            os.close(self.ext_r)
            os.close(self.ext_w)

            # Start child loop
            self.start_child()

    def _child_exit(self,a, b):
        os.close(self.ext_r)
        os.close(self.ext_w)
        self._create()

    def write_to_child(self, message):
        os.write(self.ext_w, message)

    def read(self, fd):
        buf = ""
        while 1:
            data = fd.recv(4096)
            if len(data) == 0:
                break
            else:
                buf += data
                if buf[-4:] == '\r\n\r\n':
                    break;
   
        try:
            if os.environ['PALM_DEBUG'] is not None:
                print buf
        except:
            pass

        return buf

    def parse_request(self, data):
        arr = data.split('\r\n')
        for line in arr[:-2]:
            # print line
            if line == arr[0]:
                request = Request(line)
                continue

            sep = line.find('=')
            if sep < 0:
                continue

            key = line[:sep]
            val = line[sep+1:]

            request.add_header(key, val)

        try:
            if os.environ['PALM_DEBUG'] is not None:
                for h in request.headers:
                    print h + ' = \'' + request.headers[h] + '\''
        except:
            pass

        return request

    def start_child(self):
        # Creating epoll for read pipe side
        while 1:
            remote, info = self._s.accept()
            # print "Got connection! I won! ->", os.getpid()
            buf = self.read(remote)
            #print "reading, ", buf

            request = self.parse_request(buf)

            if self.c['bin'] is None:
                bin = request.resource
            else:
                bin = self.c['bin']

            if self.c['opts'] is None and bin != request.resource:
                opts = [request.resource]
            else:
                opts = self.c['opts']
                opts.append(request.resource)

            os.dup2(remote.fileno(), sys.stdout.fileno())
            try:
                os.execve(bin, opts, request.headers)
            except:
                exit(1)

    
    def write_to_parent(self, message):
        time.sleep(1)
        n = os.write(self.int_w, message)
        print "Child wrote: ", n

    def read_data(self, fd):
        buf = os.read(fd, 1024)
        os.write(self.int_w, buf)
        print "Child got: ", buf

    def get_pid(self):
        return self._pid

    def kill(self):
        os.kill(self._pid, signal.SIGKILL)

class Request:
    def __init__(self, resource):
        self.resource = resource
        self.headers = {}

    def add_header(self, key, val):
        self.headers[key] = val
        # print self.headers

