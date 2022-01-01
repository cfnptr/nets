# Copyright 2020-2022 Nikita Fediuchin. All rights reserved.
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

if (${CMAKE_SOURCE_DIR} MATCHES ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "Prevented in-tree build")
endif ()

if (TARGET mpnw)
	return()
endif ()

project(mpnw 
	VERSION 1.3.0
	DESCRIPTION "Multi-platform networking library"
	HOMEPAGE_URL "https://github.com/cfnptr/mpnw"
	LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

option(MPNW_BUILD_SHARED "Build MPNW shared library" ON)
option(MPNW_BUILD_EXAMPLES "Build MPNW usage examples" ON)
option(MPNW_USE_OPENSSL "Use OpenSSL for secure communication" ON)
option(MPNW_ALLOW_DEPRECATED_SSL "Allow deprecated OpenSSL functions" OFF)

if (MPNW_USE_OPENSSL)
	if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
		set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@3 CACHE FILEPATH "" FORCE)
		set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.a CACHE FILEPATH "" FORCE)
		set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.a CACHE FILEPATH "" FORCE)
	endif ()

	find_package(OpenSSL)

	if (OpenSSL_FOUND)
		set(MPNW_SUPPORT_OPENSSL 1)
	else ()
		set(MPNW_SUPPORT_OPENSSL 0)
	endif ()

	if (MPNW_ALLOW_DEPRECATED_SSL)
		set(MPNW_SUPPORT_DEPRECATED_SSL 1)
	else ()
		set(MPNW_SUPPORT_DEPRECATED_SSL 0)
	endif ()
else ()
	set(MPNW_SUPPORT_OPENSSL 0)
	set(MPNW_SUPPORT_DEPRECATED_SSL 0)
endif ()

include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

if (IS_BIG_ENDIAN)
	set(MPNW_LITTLE_ENDIAN 0)
else ()
	set(MPNW_LITTLE_ENDIAN 1)
endif ()

set(MPMT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(libraries/mpmt)

configure_file(
	cmake/defines.h.in
	mpnw/defines.h)

set(MPNW_LINK_LIBRARIES
	mpmt)

if(MPNW_USE_OPENSSL)
	list(APPEND MPNW_LINK_LIBRARIES
		OpenSSL::SSL
		OpenSSL::Crypto)
endif ()

set(MPNW_SOURCES
	source/datagram_client.c
	source/datagram_server.c
	source/socket.c
	source/stream_client.c
	source/stream_server.c)

add_library(mpnw-static STATIC
	${MPNW_SOURCES})
set_target_properties(mpnw-static PROPERTIES
	OUTPUT_NAME "mpnw")
target_link_libraries(mpnw-static PUBLIC
	${MPNW_LINK_LIBRARIES})
target_include_directories(mpnw-static PUBLIC
	${PROJECT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/include)

if (MPNW_BUILD_SHARED)
	add_library(mpnw-shared SHARED
		${MPNW_SOURCES})
	set_target_properties(mpnw-shared PROPERTIES
		OUTPUT_NAME "mpnw"
		WINDOWS_EXPORT_ALL_SYMBOLS ON)
	target_link_libraries(mpnw-shared PUBLIC
		${MPNW_LINK_LIBRARIES})
	target_include_directories(mpnw-shared PUBLIC
		${PROJECT_BINARY_DIR}
		${PROJECT_SOURCE_DIR}/include)
endif ()

if (MPNW_BUILD_EXAMPLES)
	add_executable(mpnw-datagram-example
		examples/datagram_example.c)
	target_link_libraries(mpnw-datagram-example PRIVATE
		mpnw-static)
	target_include_directories(mpnw-datagram-example PRIVATE
		${PROJECT_BINARY_DIR}
		${PROJECT_SOURCE_DIR}/include)

	add_executable(mpnw-https-example
		examples/https_example.c)
	target_link_libraries(mpnw-https-example PRIVATE
		mpnw-static)
	target_include_directories(mpnw-https-example PRIVATE
		${PROJECT_BINARY_DIR}
		${PROJECT_SOURCE_DIR}/include)
endif ()
