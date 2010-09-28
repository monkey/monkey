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
        offset = 0
        length = len(data)
        lines = []
        post_data = None
        request = None

        while offset < length:
            if data[offset:offset+10] == 'POST_VARS=':
                post_data = data[offset+10:length - 8]
                offset = length
                break
            else:
                end = offset + data[offset:].find('\r\n')
                lines.append(data[offset:end])
                offset = end + 2

        for line in lines:
            # print line
            if line == lines[0]:
                request = Request(line)
                continue

            sep = line.find('=')
            if sep < 0:
                continue

            key = line[:sep]
            val = line[sep+1:]

            # Register key value
            request.add_header(key, val)

        if request is None:
            debug("[+] Invalid Exit")
            exit(1)

        if post_data is not None and request.headers.has_key('CONTENT_LENGTH'):
            content_length = int(request.get('CONTENT_LENGTH'))
            request.post_data = post_data

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

            # Any output to socket
            os.dup2(remote.fileno(), sys.stdout.fileno())

            # Handle POST method
            if request.headers['REQUEST_METHOD'] == 'POST':
                content_length = int(request.get('CONTENT_LENGTH'))

                # Use pipe() for small post data
                if content_length <= 65536:
                    # Temporal Pipe > STDIN
                    pipe_r, pipe_w = os.pipe()
                    os.dup2(remote.fileno(), sys.stdout.fileno())
                    os.dup2(pipe_r, sys.stdin.fileno())
                    os.write(pipe_w, request.post_data)
                else:
                    # Pipes
                    pipe_write = os.pipe()
                                        
                    pid = os.fork()
                    if pid != 0: # parent
                        os.close(pipe_write[0])
                        os.write(pipe_write[1], request.post_data)
                        os.close(pipe_write[1])

                        try:
                            os.waitpid(pid, 0)
                        except:
                            pass
                        exit(0)

                    # Child
                    os.dup2(pipe_write[0], sys.stdin.fileno())
                        
            # Launch process
            os.execve(bin, opts, request.headers)

            """
            except:
                print "Content-Type: text/plain\r\n\r\n"

                print "*** PALM INTERNAL ERROR ***"
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
                """
    def get_pid(self):
        return self._pid

    def kill(self):
        os.kill(self._pid, signal.SIGKILL)

class Request:
    def __init__(self, resource):
        self.resource = resource
        self.headers = {}
        self.post_data = None

    def __str__(self):
        ret = str(self.resource) + ' ' + str(self.headers);
        return ret

    def add_header(self, key, val):
        self.headers[key] = val

    def get(self, key):
        return self.headers[key]
