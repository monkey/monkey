# Monkey Server

[Monkey](http://monkey-project.com) is a fast and lightweight Web Server for Linux. It has been designed to be very scalable with low memory and CPU consumption, the perfect solution for Embedded Linux and high end production environments.

Monkey was started in 2001 as an open source project. It is currently licensed under the Apache License v2. Monkey community is well established and available through the mailing list or in the Freenode IRC channel

Besides the common features as HTTP server, it expose a flexible C API which aims to behave as a fully HTTP development framework, so it can be extended as desired through the plugins interface.

The server is designed as a small core extensible through its plugin interface. The binary size of Monkey is around 100 KB and around 250 KB on runtime depending on the loaded plugins. Monkey can perform well on x86 and x86-64, and ARM architectures running Linux embedded variants.

For more details please refer to the [official documentation](http://monkey-project.com/documentation/).

## Features

- HTTP/1.1 Compliant
- Hybrid Networking Model: Asynchronous mode + fixed Threads
- Indented configuration style
- Versatile plugin subsystem / API
- x86, x86_64 & ARM compatible
- More features:
  - SSL
  - IPv6
  - Basic Auth
  - Log writer
  - Security
  - Directory Listing
  - CGI
  - FastCGI
  - Much more!
- Embeddable as a shared library
- Monkey HTTP Server Workers: event loop
- Web Services What do we usually expect 

## Requirements

When building Monkey it needs:

- CMake >= 2.8
- Glibc >= 2.5
- GNU C Compiler >= 3.2

Monkey requires the following components on runtime:

- Linux Kernel >= 2.6.32
- Pthreads support

## Writing Scalable Web Services

If you are interested into use [Monkey](http://monkey-project.com) as a base platform build scalable web services, we recommend you check our [Duda I/O](http://duda.io) project made for that purpose.

## Join us!

Monkey is an open organization so we want to hear about you, we continue growing and you can be part of it!, you can reach us at:

- Mailing list: http://lists.monkey-project.com
- IRC: irc.freenode.net #monkey
- Twitter: http://www.twitter.com/monkeywebserver
- Linkedin: http://www.linkedin.com/groups/Monkey-HTTP-Daemon-3211216
- Freecode: http://freecode.com/projects/monkey (R.I.P)

If you want to get involved, please also refer to our [Contributing](https://github.com/monkey/monkey/blob/master/CONTRIBUTING.md) guidelines.

## Author

Eduardo Silva <eduardo@monkey.io>
