cmake_minimum_required(VERSION 3.10)

if(${CMAKE_SOURCE_DIR} MATCHES ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "Prevented in-tree build")
endif()

project(mpnw 
	VERSION 0.1.0
	LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

configure_file(
	cmake/defines.h.in
	mpnw/defines.h)

add_subdirectory(libraries/mpmt)

add_library(mpnw STATIC
	source/mpnw/client_socket.c
	source/mpnw/socket.c
	source/mpnw/stream_server.c)
target_link_libraries(mpnw PRIVATE
	mpmt)
target_include_directories(mpnw PUBLIC
	${PROJECT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/include)
