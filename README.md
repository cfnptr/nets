# Nets

A library providing generic interface for transferring data over a **network** across different platforms.

## Features

* Blocking / non-blocking socket
* Stream client / server (TCP)
* Datagram client / server (UDP)
* Secure socket layer (SSL, TLS)
* Datagrams over TCP stream
* C and C++ implementations

## Supported operating systems

* Windows (10/11)
* Ubuntu (22.04/24.04)
* macOS (14/15)

This list includes only those systems on which functionality testing is conducted.
However, you can also compile it under any other Linux distribution or operating system.

## Build requirements

* C99 compiler
* C++17 compiler (optional)
* [Git 2.30+](https://git-scm.com/)
* [CMake 3.22+](https://cmake.org/)
* [vcpkg](https://learn.microsoft.com/en-us/vcpkg/) (Windows only)
* [brew](https://brew.sh/) (macOS only)

Use building [instructions](BUILDING.md) to install all required tools and libraries.

### CMake options

| Name                      | Description                          | Default value |
|---------------------------|--------------------------------------|---------------|
| NETS_BUILD_EXAMPLES       | Build Nets usage examples            | `ON`          |
| NETS_USE_OPENSSL          | Use OpenSSL for secure communication | `ON`          |
| NETS_ALLOW_DEPRECATED_SSL | Allow deprecated OpenSSL functions   | `OFF`         |

## Cloning

```
git clone --recursive https://github.com/cfnptr/nets
```

## Building ![CI](https://github.com/cfnptr/nets/actions/workflows/cmake.yml/badge.svg)

* Windows: ```./scripts/build-release.bat```
* macOS / Ubuntu: ```./scripts/build-release.sh```

## Third-party

* [cURL](https://github.com/curl/curl) (curl License)
* [mpmt](https://github.com/cfnptr/mpmt/) (Apache-2.0 License)
* [mpio](https://github.com/cfnptr/mpio/) (Apache-2.0 License)
* [OpenSSL](https://github.com/openssl/openssl/) (Apache-2.0 License)
* [zlib](https://github.com/madler/zlib) (zlib License)

### Inspired by

* [asio](https://github.com/boostorg/asio/)
* [libuv](https://github.com/libuv/libuv/)

### Special thanks to Gigaflops.