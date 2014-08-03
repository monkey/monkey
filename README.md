# Monkey HTTP Server

Monkey HTTP Server is a fast and lightweight Web Server for Linux. It has been designed to be very scalable with low memory and CPU consumption, the perfect solution for Embedded Linux and/or high production environments.

Besides the common features as HTTP server, it expose a flexible C API which aims to behave as a fully HTTP development framework, so it can be extended as desired through the plugins interface.

For more details please refer to the [official documentation](http://monkey-project.com/documentation/).

## Features

- HTTP/1.1 Compliant
- Hybrid Networking Model: Asynchronous mode + fixed Threads
- Indented configuration style
- Versatile plugin subsystem / API
- x86 & x86_64 architectures compatible (including ARM processors)
- Common features: SSL, IPv6, Basic Auth, log writer, security, directory listing, CGI, FastCGI, etc.
- Embeddable as a shared library (only one context supported currently)

## Requirements

Monkey requires the following components:

- Linux Kernel >= 2.6.32
- Glibc >= 2.5
- Pthreads
- GNU C Compiler >= 3.2

## Join us!

Monkey is an open organization so we want to hear about you, we continue growing and you can be part of it!, you can reach us at:

- Mailing list: http://lists.monkey-project.com
- IRC: irc.freenode.net #monkey
- Twitter: http://www.twitter.com/monkeywebserver
- Linkedin: http://www.linkedin.com/groups/Monkey-HTTP-Daemon-3211216
- Freecode: http://freecode.com/projects/monkey (R.I.P)

We are open to suggestions and criticisms, if you have an idea, found a bug, don't hesitate to report it to find a solution and if you have it, send it to include your code.

## Author

Eduardo Silva <eduardo@monkey.io>
