cmake_minimum_required(VERSION 3.10)

if(${CMAKE_SOURCE_DIR} MATCHES ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "Prevented in-tree build")
endif()

project(mpnw 
	VERSION 1.0.0
	DESCRIPTION "Multi-platform networking library"
	HOMEPAGE_URL "https://github.com/cfnptr/mpnw"
	LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

option(MPNW_USE_OPENSSL "Use OpenSSL for secure communication" ON)

if(MPNW_USE_OPENSSL)
	set(MPNW_HAS_OPENSSL 1)

	if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
		set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl@1.1/1.1.1i CACHE FILEPATH "" FORCE)
		set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.dylib CACHE FILEPATH "" FORCE)
		set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib CACHE FILEPATH "" FORCE)
	endif()

	find_package(OpenSSL REQUIRED)
else()
	set(MPNW_HAS_OPENSSL 0)
endif()

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
endif()

add_library(mpnw STATIC
	source/mpnw/datagram_client.c
	source/mpnw/datagram_server.c
	source/mpnw/http_client.c
	source/mpnw/http_server.c
	source/mpnw/socket.c
	source/mpnw/stream_client.c
	source/mpnw/stream_server.c)
target_link_libraries(mpnw PUBLIC
	${MPNW_LINK_LIBRARIES})
target_include_directories(mpnw PUBLIC
	${PROJECT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/include)
