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
import fcntl
from debug import *

class Child:
    def __init__(self, name, socket, parent):
        # Listener socket
        self.name = name
        self._s = socket

        # Parent Object
        self.parent = parent
        self.split_conf()

        # On child end, re-create it
	signal.signal(signal.SIGCHLD, self._child_exit)

        # Start our child
        self._create()

    def split_conf(self):
        try:
            opts = self.parent.opts.split()
        except:
            opts = []

        self.c = {'bin': self.parent.bin, 'opts': opts}

    def _create(self):
        # Fork process
        pid = os.fork()
        if pid:
            self._pid = pid
            msg = "    Creating '%s' child PID %i" % (self.name, pid)
            debug(msg)
        else:
            # Start child loop
            self.start_loop()

    def _child_exit(self,a, b):
        os.wait() 
        debug("[-] Exit child '%s'" % self.name)
        self._create()

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

        return buf

    def parse_request(self, data):
        arr = data.split('\r\n')
        request = None

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

            if key == 'POST_VARS' and len(val) > 0:
                val = '*'

            # Register key value
            request.add_header(key, val)

        if request is None:
            debug("[+] Invalid Exit")
            exit(1)

        # Post-parse POST data
        if request.get('POST_VARS') == '*':
            init_key = '\r\nPOST_VARS='
            len_key = len(init_key)

            post_len = int(request.get('CONTENT_LENGTH'))
            post_data = data.find(init_key)

            # Set string offsets
            offset_init = post_data + len_key
            offset_end = post_data + len_key + post_len

            # Override POST_VARS
            request.add_header('POST_VARS', data[offset_init:offset_end])

        # Debug message
        msg = "[+] Request Headers\n"
        for h in request.headers:
            msg += '    ' + h + ' = \'' + request.headers[h] + '\'\n'
        msg += "[-] Request End"   
        debug(msg)

        return request

    def start_loop(self):
        # Creating epoll for read pipe side
        while 1:
            remote, info = self._s.accept()
            remote_fd = remote.fileno()
            
            # Close on exec
	    flags = fcntl.fcntl(remote_fd, fcntl.F_GETFD)
            try:
                flags |= fcntl.FD_CLOEXEC
            except AttributeError, e:
                flags |= 1

            fcntl.fcntl(remote_fd, fcntl.F_SETFD, flags)

            debug("[+] |%s| Request arrived [PID=%i]" % (self.name, os.getpid()))

            buf = self.read(remote)
            print buf
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

            print "***"
            print request.headers['POST_VARS']
            print "***"
            try:
                os.dup2(remote.fileno(), sys.stdout.fileno())

                # Write Post data to STDIN (Pipe)
                if request.headers['REQUEST_METHOD'] == 'POST':
                    # Temporal Pipe > STDIN
                    pipe_r, pipe_w = os.pipe()
                    os.dup2(pipe_r, sys.stdin.fileno())
                    os.write(pipe_w, request.headers['POST_VARS'])

                os.execve(bin, opts, request.headers)
            except:
                print "Content-Type: text/plain\r\n\r\n"

                print "*** INTERNAL ERROR ***"
                print 

                print "Child Executing"
                print "---------------"
                print bin, opts

                print
                print "Palm Enviroment variables"
                print "-------------------------"
                for h in request.headers:
                    print h, "=", request.headers[h]

                exit(1)

    def get_pid(self):
        return self._pid

    def kill(self):
        os.kill(self._pid, signal.SIGKILL)

class Request:
    def __init__(self, resource):
        self.resource = resource
        self.headers = {}

    def __str__(self):
        ret = str(self.resource) + ' ' + str(self.headers);
        return ret

    def add_header(self, key, val):
        self.headers[key] = val

    def get(self, key):
        return self.headers[key]
