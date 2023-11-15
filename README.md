# Nets ![CI](https://github.com/cfnptr/nets/actions/workflows/cmake.yml/badge.svg)

A library providing generic interface for transferring data over a **network** across different platforms.

## Features

* Blocking / non-blocking socket
* Stream client / server (TCP)
* Datagram client / server (UDP)
* Secure socket layer (OpenSSL)
* Datagrams over TCP stream
* HTTP client (TLS, Compression)

## Supported operating systems

* Ubuntu
* MacOS
* Windows

## Build requirements

* C99 compiler
* [Git 2.30+](https://git-scm.com/)
* [CMake 3.10+](https://cmake.org/)
* [OpenSSL 1.1.1+](https://openssl.org/) (Optional)

### OpenSSL installation

* Ubuntu: sudo apt install libssl-dev
* MacOS: [brew](https://brew.sh/) install openssl
* Windows: [choco](https://chocolatey.org/) install openssl

### CMake options

| Name                      | Description                          | Default value |
|---------------------------|--------------------------------------|---------------|
| NETS_BUILD_SHARED         | Build Nets shared library            | `ON`          |
| NETS_BUILD_EXAMPLES       | Build Nets usage examples            | `ON`          |
| NETS_USE_OPENSSL          | Use OpenSSL for secure communication | `ON`          |
| NETS_ALLOW_DEPRECATED_SSL | Allow deprecated OpenSSL functions   | `OFF`         |

## Cloning

```
git clone --recursive https://github.com/cfnptr/nets
```

## Usage examples

Datagram client / server example: [examples/datagram_example.c](https://github.com/cfnptr/nets/blob/main/examples/datagram_example.c)<br/>
HTTPS client (OpenSSL) example: [examples/https_example.c](https://github.com/cfnptr/nets/blob/main/examples/https_example.c)

## Third-party

* [mpmt](https://github.com/cfnptr/mpmt/) (Apache-2.0 License)
* [OpenSSL](https://github.com/openssl/openssl/) (Apache-2.0 License)
* [zlib](https://github.com/madler/zlib) (zlib License)

### Inspired by

* [asio](https://github.com/boostorg/asio/)
* [libuv](https://github.com/libuv/libuv/)

### Special thanks to Gigaflops.
