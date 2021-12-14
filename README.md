# MPNW
A library providing a generic interface for transferring data over a network across different platforms.

![CI](https://github.com/cfnptr/mpnw/actions/workflows/cmake.yml/badge.svg)

## Features
* Blocking / non-blocking socket
* Stream client / server (TCP)
* Datagram client / server (UDP)
* Secure socket layer (OpenSSL)
* Datagrams over TCP stream

## Supported operating systems
* Ubuntu
* MacOS
* Windows

## Build requirements
* C99 compiler
* [CMake 3.10+](https://cmake.org/)
* [OpenSSL](https://openssl.org/) (Optional)

## OpenSSL installation
* Ubuntu: sudo apt install libssl-dev
* MacOS: [brew](https://brew.sh/) install openssl
* Windows: [choco](https://chocolatey.org/) install openssl

## Cloning
```
git clone https://github.com/cfnptr/mpnw
cd mpnw
git submodule update --init --recursive
```

## Building
```
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build/
cmake --build build/
```

### CMake options
| Name                      | Description                          | Default value |
|---------------------------|--------------------------------------|---------------|
| MPNW_BUILD_SHARED         | Build MPNW shared library            | ON            |
| MPNW_BUILD_EXAMPLES       | Build MPNW usage examples            | ON            |
| MPNW_USE_OPENSSL          | Use OpenSSL for secure communication | ON            |
| MPNW_ALLOW_DEPRECATED_SSL | Allow deprecated OpenSSL functions   | OFF           |

## Usage
Datagram client / server example: [examples/datagram_example.c](https://github.com/cfnptr/mpnw/blob/main/examples/datagram_example.c) \
HTTPS client (OpenSSL) example: [examples/https_example.c](https://github.com/cfnptr/mpnw/blob/main/examples/https_example.c)

## Third-party
* [mpmt](https://github.com/cfnptr/mpmt/) (Apache-2.0 License)
* [OpenSSL](https://github.com/openssl/openssl/) (Apache-2.0 License)

### Special thanks to Gigaflops.
