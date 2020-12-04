#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* Internet Protocol V4 any address */
#define ANY_IP_ADDRESS_V4 "0.0.0.0"
/* Internet Protocol V6 any address */
#define ANY_IP_ADDRESS_V6 "::"

/* Internet protocol V4 loopback address */
#define LOOPBACK_IP_ADDRESS_V4 "127.0.0.1"
/* Internet protocol V6 loopback address */
#define LOOPBACK_IP_ADDRESS_V6 "::1"

#define ANY_IP_ADDRESS_PORT "0"

/* Socket instance handle */
struct Socket;
/* Socket address instance handle */
struct SocketAddress;

/* Socket internet protocol address family */
enum AddressFamily
{
	UNKNOWN_ADDRESS_FAMILY,
	IP_V4_ADDRESS_FAMILY,
	IP_V6_ADDRESS_FAMILY,
};

/* Socket communication type */
enum SocketType
{
	UNKNOWN_SOCKET_TYPE,
	STREAM_SOCKET_TYPE,
	DATAGRAM_SOCKET_TYPE,
};

/* Socket connection shutdown */
enum SocketShutdown
{
	SHUTDOWN_RECEIVE_ONLY,
	SHUTDOWN_SEND_ONLY,
	SHUTDOWN_RECEIVE_SEND,
};

/* Returns true if network was initialized. */
bool initializeNetwork();
/* Terminates network. */
void terminateNetwork();

/*
 * Creates a new socket.
 * Return socket on success, otherwise null.
 *
 * type - socket communication type.
 * family - internet protocol address family.
 */
struct Socket* createSocket(
	enum SocketType type,
	enum AddressFamily family);

/*
 * Destroys specified socket.
 * Shutdowns socket before destruction.
 *
 * socket - pointer to the valid socket.
 */
void destroySocket(
	struct Socket* socket);

/*
 * Return socket communication type.
 * socket - pointer to the valid socket.
 */
enum SocketType getSocketType(
	const struct Socket* socket);

/*
 * Returns true if socket is in listening state.
 * socket - pointer to the valid socket.
 */
bool isSocketListening(
	const struct Socket* socket);

/*
 * Returns a new local address on success, otherwise null.
 * socket - pointer to the valid socket.
 */
struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket);

/*
 * Returns a new remote address on success, otherwise null.
 * socket - pointer to the valid socket.
 */
struct SocketAddress* getSocketRemoteAddress(
	const struct Socket* socket);

/*
 * Returns true if socket is in blocking mode.
 * socket - pointer to the valid socket.
 */
bool getSocketBlocking(
	const struct Socket* socket);

/*
 * Sets socket to the specified blocking mode.
 * socket - pointer to the valid socket.
 */
void setSocketBlocking(
	struct Socket* socket,
	bool blocking);

/*
 * Returns socket message receive timeout time.
 * socket - pointer to the valid socket.
 */
size_t getSocketReceiveTimeout(
	const struct Socket* socket);

/*
 * Sets socket message receive timeout time.
 * socket - pointer to the valid socket.
 */
void setSocketReceiveTimeout(
	struct Socket* socket,
	size_t milliseconds);

/*
 * Returns socket message send timeout time.
 * socket - pointer to the valid socket.
 */
size_t getSocketSendTimeout(
	const struct Socket* socket);

/*
 * Sets socket message send timeout time.
 * socket - pointer to the valid socket.
 */
void setSocketSendTimeout(
	struct Socket* socket,
	size_t milliseconds);

/*
 * Binds specified address to the socket.
 * Returns true if socket bound successfully.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool bindSocket(
	struct Socket* socket,
	const struct SocketAddress* address);

/*
 * Starts socket listening for a new connections.
 * Returns true if socket listening successfully.
 *
 * socket - pointer to the valid socket.
 */
bool listenSocket(
	struct Socket* socket);

/*
 * Returns a new socket on success, otherwise null.
 * socket - pointer to the valid socket.
 */
struct Socket* acceptSocket(
	struct Socket* socket);

/*
 * Starts connection to the specified address.
 * Returns true if socket connected successfully.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool connectSocket(
	struct Socket* socket,
	const struct SocketAddress* address);

/*
 * Shutdowns part of the full-duplex connection.
 * Returns true if socket shutdown successfully.
 *
 * socket - pointer to the valid socket.
 * type - socket connection shutdown.
 */
bool shutdownSocket(
	struct Socket* socket,
	enum SocketShutdown type);

/*
 * Returns true on successful socket message receive.
 *
 * socket - pointer to the valid socket.
 * buffer - pointer to the valid receive buffer.
 * size - message receive buffer size.
 * count - pointer to the valid receive byte count.
 */
bool socketReceive(
	struct Socket* socket,
	void* buffer,
	size_t size,
	size_t* count);

/*
 * Returns true on successful socket message send.
 *
 * socket - pointer to the valid socket.
 * buffer - pointer to the valid send buffer.
 * count - message byte count to send.
 */
bool socketSend(
	struct Socket* socket,
	const void* buffer,
	size_t count);

/*
 * Returns true on successful socket message receive.
 * Sets a new message sender address on success.
 *
 * socket - pointer to the valid socket.
 * buffer - pointer to the valid receive buffer.
 * size - message receive buffer size.
 * address - pointer to the valid sender address.
 * count - pointer to the valid receive byte count.
 */
bool socketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress** address,
	size_t* count);

/*
 * Returns true on successful socket message send.
 *
 * socket - pointer to the valid socket.
 * buffer - pointer to the valid send buffer.
 * count - message byte count to send.
 * address - pointer to the valid receiver address.
 */
bool socketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t count,
	const struct SocketAddress* address);

/*
 * Returns a new address on success, otherwise null.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 */
struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service);

/*
 * Destroys specified socket endpoint address.
 */
void destroySocketAddress(
	struct SocketAddress* address);

/*
 * Returns address family on success, otherwise unknown.
 * address - pointer to the valid socket address.
 */
enum AddressFamily getSocketAddressFamily(
	const struct SocketAddress* address);

/*
 * Returns true on success IP address get.
 *
 * address - pointer to the valid socket address.
 * ip - pointer to the valid byte array.
 * size - pointer to the valid byte array size.
 */
bool getSocketAddressIP(
	const struct SocketAddress* address,
	uint8_t** ip,
	size_t* size);

/*
 * Returns port number on success, otherwise zero.
 * address - pointer to the valid socket address.
 */
uint16_t getSocketAddressPort(
	const struct SocketAddress* address);

/*
 * Returns a new host name on success, otherwise null.
 * address - pointer to the valid socket address.
 */
char* getSocketAddressHost(
	const struct SocketAddress* address);

/*
 * Returns a new service name on success, otherwise null.
 * address - pointer to the valid socket address.
 */
char* getSocketAddressService(
	const struct SocketAddress* address);

/*
 * Returns true on success host and service get.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid host name string.
 * service - pointer to the valid host name string.
 */
bool getSocketAddressHostService(
	const struct SocketAddress* address,
	char** host,
	char** service);
