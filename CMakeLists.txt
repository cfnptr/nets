cmake_minimum_required(VERSION 3.10)

if(${CMAKE_SOURCE_DIR} MATCHES ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "Prevented in-tree build")
endif()

project(mpnw 
	VERSION 1.0.0
	DESCRIPTION "An open-source multi-platform networking library"
	HOMEPAGE_URL "https://github.com/cfnptr/mpnw"
	LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

configure_file(
	cmake/defines.h.in
	mpnw/defines.h)

add_subdirectory(libraries/mpmt)

add_library(mpnw STATIC
	source/mpnw/socket.c
	source/mpnw/stream_socket.c)
target_link_libraries(mpnw PUBLIC
	mpmt)
target_include_directories(mpnw PUBLIC
	${PROJECT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/include)
