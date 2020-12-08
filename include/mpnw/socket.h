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

/* Current computer IP address */
#define LOCALHOST_HOSTNAME "localhost"
/* System-allocated, dynamic port */
#define ANY_IP_ADDRESS_PORT "0"

/* Socket instance handle */
struct Socket;
/* Socket address instance handle */
struct SocketAddress;

/* Socket internet protocol address family */
enum AddressFamily
{
	IP_V4_ADDRESS_FAMILY,
	IP_V6_ADDRESS_FAMILY,
};

/* Socket communication type */
enum SocketType
{
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
/* Returns true if network is initialized */
bool getNetworkInitialized();

/*
 * Creates a new socket.
 * Returns socket on success, otherwise null.
 *
 * type - socket communication type.
 * family - internet protocol address family.
 */
struct Socket* createSocket(
	enum SocketType type,
	enum AddressFamily family);

/*
 * Destroys specified socket.
 * socket - pointer to the valid socket.
 */
void destroySocket(
	struct Socket* socket);

/*
 * Returns socket connection type.
 * socket - pointer to the valid socket.
 */
enum SocketType getSocketType(
	const struct Socket* socket);

/*
 * Gets a new local socket address.
 * Returns address on success, otherwise null.
 *
 * socket - pointer to the valid socket.
 */
struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket);

/*
 * Gets a new remote socket address.
 * Returns address on success, otherwise null.
 *
 * socket - pointer to the valid socket.
 */
struct SocketAddress* getSocketRemoteAddress(
	const struct Socket* socket);

/*
 * Binds specified address to the socket.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool bindSocket(
	struct Socket* socket,
	const struct SocketAddress* address);

/*
 * Starts socket listening for a new connections.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 */
bool listenSocket(
	struct Socket* socket);

/*
 * Accepts a new socket connection.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * acceptedSocket - pointer to the valid socket.
 */
bool acceptSocket(
	struct Socket* socket,
	struct Socket** acceptedSocket);

/*
 * Starts connection to the specified address.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool connectSocket(
	struct Socket* socket,
	const struct SocketAddress* address);

/*
 * Shutdowns part of the full-duplex connection.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * type - socket connection shutdown.
 */
bool shutdownSocket(
	struct Socket* socket,
	enum SocketShutdown type);

/*
 * Receives socket message.
 * Returns true on success.
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
 * Sends socket message.
 * Returns true on success.
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
 * Receives socket message from a new address.
 * Returns true on success.
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
 * Receives socket message to the specified address.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * buffer - pointer to the valid send buffer.
 * count - message byte count to send.
 * address - pointer to the valid socket address.
 */
bool socketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t count,
	const struct SocketAddress* address);

/*
 * Creates a new socket address.
 * Returns address on success, otherwise null.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 */
struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service);

/*
 * Resolves a new socket addresses.
 * Returns address on success, otherwise null.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 * family - socket address family.
 * type - socket connection type.
 */
struct SocketAddress* resolveSocketAddress(
	const char* host,
	const char* service,
	enum AddressFamily family,
	enum SocketType type);

/*
 * Destroys specified socket endpoint address.
 * address - pointer to the valid socket address.
 */
void destroySocketAddress(
	struct SocketAddress* address);

/*
 * Creates a new socket address copy.
 * Returns address on success, otherwise null.
 *
 * address - pointer to the valid socket address.
 */
struct SocketAddress* copySocketAddress(
	const struct SocketAddress* address);

/*
 * Compares two addresses.
 *
 * a - pointer to the valid socket address.
 * b - pointer to the valid socket address.
 */
int compareSocketAddress(
	const struct SocketAddress* a,
	const struct SocketAddress* b);

/*
 * Returns socket address family.
 * address - pointer to the valid socket address.
 */
enum AddressFamily getSocketAddressFamily(
	const struct SocketAddress* address);

/*
 * Returns a new socket IP address byte array.
 * Returns IP address on success, otherwise null.
 *
 * address - pointer to the valid socket address.
 * size - pointer to the valid byte array size.
 */
uint8_t* getSocketAddressIP(
	const struct SocketAddress* address,
	size_t * size);

/*
 * Returns socket address port number.
 * address - pointer to the valid socket address.
 */
uint16_t getSocketAddressPort(
	const struct SocketAddress* address);

/*
 * Returns a new socket address host name.
 * Returns host on success, otherwise null.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid socket host name.
 */
char* getSocketAddressHost(
	const struct SocketAddress* address);

/*
 * Returns a new socket address service name string.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * service - pointer to the valid socket service name.
 */
char* getSocketAddressService(
	const struct SocketAddress* address);

/*
 * Returns a new socket address host and service name.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid host name string.
 * service - pointer to the valid host name string.
 */
bool getSocketAddressHostService(
	const struct SocketAddress* address,
	char** host,
	char** service);
