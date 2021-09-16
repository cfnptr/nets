## Features
* Blocking/Non-blocking socket
* Stream client/server (TCP)
* Datagram client/server (UDP)
* Secure socket layer (OpenSSL)

## Supported operating systems
* Ubuntu
* MacOS
* Windows

## Build requirements
* C99 compiler
* [CMake 3.10+](https://cmake.org/)
* [OpenSSL](https://openssl.org/)

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
| Name                | Description                          | Default value |
| ------------------- | ------------------------------------ | ------------- |
| MPNW_BUILD_EXAMPLES | Build MPNW usage examples            | ON            |
| MPNW_USE_OPENSSL    | Use OpenSSL for secure communication | ON            |


## Third-party
* [mpmt](https://github.com/cfnptr/mpmt/) (BSD-3-Clause License)
* [OpenSSL](https://github.com/openssl/openssl/) (Apache 2.0 License)

### Special thanks to Gigaflops.
