# Copyright 2020-2026 Nikita Fediuchin. All rights reserved.
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

cmake_minimum_required(VERSION 3.22)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "Prevented in-tree build")
endif()

if(TARGET nets-static)
	return()
endif()

include(cmake/package-managers.cmake)

project(nets VERSION 3.0.0 LANGUAGES C
	DESCRIPTION "Secure multi-platform networking library \
		with implemented TCP / UDP server and client"
	HOMEPAGE_URL "https://github.com/cfnptr/nets")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

option(NETS_BUILD_EXAMPLES "Build Nets usage examples" ON)
option(NETS_USE_OPENSSL "Use OpenSSL for secure communication" ON)
option(NETS_USE_CURL "Use cURL for HTTP requests" ON)

if(NETS_USE_OPENSSL)
	find_package(OpenSSL)
	if(NOT OpenSSL_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
		set(OPENSSL_SSL_LIBRARY /usr/lib/libssl.so)
		set(OPENSSL_CRYPTO_LIBRARY /usr/lib/libcrypto.so)
	endif()

	find_package(OpenSSL)
	if(OpenSSL_FOUND)
		set(NETS_SUPPORT_OPENSSL 1)
	else()
		set(NETS_SUPPORT_OPENSSL 0)
	endif()
else()
	set(NETS_SUPPORT_OPENSSL 0)
endif()

if(NETS_USE_CURL)
	find_package(CURL)
	if(CURL_FOUND)
		set(NETS_SUPPORT_CURL 1)
	else()
		set(NETS_SUPPORT_CURL 0)
	endif()
else()
	set(NETS_SUPPORT_CURL 0)
endif()

include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

if(IS_BIG_ENDIAN)
	set(NETS_LITTLE_ENDIAN 0)
else()
	set(NETS_LITTLE_ENDIAN 1)
endif()

set(NETS_INCLUDE_DIRECTORIES ${PROJECT_BINARY_DIR}/include
	${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/wrappers/cpp)
set(NETS_LINK_LIBRARIES mpmt-static mpio-static)

set(MPMT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MPMT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MPMT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(libraries/mpmt)

set(MPIO_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MPIO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(libraries/mpio)

configure_file(cmake/defines.h.in include/nets/defines.h)

if(NETS_USE_OPENSSL AND OpenSSL_FOUND)
	list(APPEND NETS_LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
endif()
if(NETS_USE_CURL AND CURL_FOUND)
	list(APPEND NETS_LINK_LIBRARIES CURL::libcurl)
endif()

set(NETS_SOURCES source/datagram-client.c source/datagram-server.c source/socket.c 
	source/stream-client.c source/stream-message.c source/stream-server.c)

add_library(nets-static STATIC ${NETS_SOURCES})
target_link_libraries(nets-static PUBLIC ${NETS_LINK_LIBRARIES})
target_include_directories(nets-static PUBLIC ${NETS_INCLUDE_DIRECTORIES})

if(NETS_BUILD_EXAMPLES)
	add_executable(nets-datagram-example examples/datagram-example.c)
	target_link_libraries(nets-datagram-example PRIVATE nets-static)
	target_include_directories(nets-datagram-example PRIVATE
		${PROJECT_BINARY_DIR}/include ${PROJECT_SOURCE_DIR}/include)
endif()
