# Enable TLS support

The new TLS plugin is based on the latest mbedtls-2.2.x version, before to enable the plugin make sure to install mbedtls as:

1. Get the mbedtls-2.2.1 version (mbedtls.org)

2. Unpack with and prepare:

```
$ cd mbedtls-2.2.1
$ mkdir build
```

configure, compile and install:

```
$ cmake -DCMAKE_INSTALL_PREFIX=/opt/mbedtls-2.2.1/ -DUSE_SHARED_MBEDTLS_LIBRARY=On ../
$ make
$ sudo make install
```

Now enable Monkey plugin with:

```
./configure --enable-plugins=tls
```
