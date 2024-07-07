# Copyright 2020-2023 Nikita Fediuchin. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.10)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "Prevented in-tree build")
endif()

if(TARGET nets-static)
	return()
endif()

project(nets VERSION 2.0.3 LANGUAGES C
	DESCRIPTION "Secure multi-platform networking library \
		with implemented TCP / UDP / HTTP server and client"
	HOMEPAGE_URL "https://github.com/cfnptr/nets")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

option(NETS_BUILD_SHARED "Build Nets shared library" ON)
option(NETS_BUILD_EXAMPLES "Build Nets usage examples" ON)
option(NETS_USE_OPENSSL "Use OpenSSL for secure communication" ON)
option(NETS_ALLOW_DEPRECATED_SSL "Allow deprecated OpenSSL functions" OFF)

if(NETS_USE_OPENSSL)
	if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		if(EXISTS /opt/homebrew/opt/openssl@3)
			set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3 CACHE FILEPATH "" FORCE)
		elseif(EXISTS /usr/local/opt/openssl@3) # support of old intel based macs
			set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@3 CACHE FILEPATH "" FORCE)
		endif()
		if(DEFINED OPENSSL_ROOT_DIR)
			set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.a CACHE FILEPATH "" FORCE)
			set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.a CACHE FILEPATH "" FORCE)
		endif()
	endif()

	find_package(OpenSSL)

	if(OpenSSL_FOUND)
		set(NETS_SUPPORT_OPENSSL 1)
	else()
		set(NETS_SUPPORT_OPENSSL 0)
	endif()

	if(NETS_ALLOW_DEPRECATED_SSL)
		set(NETS_SUPPORT_DEPRECATED_SSL 1)
	else()
		set(NETS_SUPPORT_DEPRECATED_SSL 0)
	endif()
else()
	set(NETS_SUPPORT_OPENSSL 0)
	set(NETS_SUPPORT_DEPRECATED_SSL 0)
endif()

include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

if(IS_BIG_ENDIAN)
	set(NETS_LITTLE_ENDIAN 0)
else()
	set(NETS_LITTLE_ENDIAN 1)
endif()

set(NETS_INCLUDE_DIRECTORIES
	${PROJECT_BINARY_DIR}/include ${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}/libraries/zlib ${PROJECT_SOURCE_DIR}/libraries/zlib)
set(NETS_LINK_LIBRARIES mpmt-static mpio-static)

set(MPMT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MPMT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MPMT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(libraries/mpmt)

set(MPIO_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MPIO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(libraries/mpio)

if(NOT TARGET zlibstatic)
	set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
	add_subdirectory(libraries/zlib)
endif()

configure_file(cmake/defines.h.in include/nets/defines.h)

if(NETS_USE_OPENSSL AND OpenSSL_FOUND)
	list(APPEND NETS_LINK_LIBRARIES
		OpenSSL::SSL OpenSSL::Crypto)
endif()

set(NETS_SOURCES
	source/datagram_client.c
	source/datagram_server.c
	source/http_client.c
	source/socket.c
	source/stream_client.c
	source/stream_server.c)

add_library(nets-static STATIC ${NETS_SOURCES})
target_link_libraries(nets-static PUBLIC ${NETS_LINK_LIBRARIES} zlibstatic)
target_include_directories(nets-static PUBLIC ${NETS_INCLUDE_DIRECTORIES})

if(NETS_BUILD_SHARED)
	add_library(nets-shared SHARED ${NETS_SOURCES})
	set_target_properties(nets-shared PROPERTIES
		OUTPUT_NAME "nets" WINDOWS_EXPORT_ALL_SYMBOLS ON)
	target_link_libraries(nets-shared PUBLIC ${NETS_LINK_LIBRARIES} zlib)
	target_include_directories(nets-shared PUBLIC ${NETS_INCLUDE_DIRECTORIES})
endif()

if(NETS_BUILD_EXAMPLES)
	add_executable(nets-datagram-example examples/datagram_example.c)
	target_link_libraries(nets-datagram-example PRIVATE nets-static)
	target_include_directories(nets-datagram-example PRIVATE
		${PROJECT_BINARY_DIR}/include ${PROJECT_SOURCE_DIR}/include)

	add_executable(nets-https-example examples/https_example.c)
	target_link_libraries(nets-https-example PRIVATE nets-static)
	target_include_directories(nets-https-example PRIVATE
		${PROJECT_BINARY_DIR}/include ${PROJECT_SOURCE_DIR}/include)
endif()