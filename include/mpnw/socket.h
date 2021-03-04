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
/* Secure socket layer context handle */
struct SslContext;

/* Socket internet protocol address family */
enum AddressFamily
{
	IP_V4_ADDRESS_FAMILY = 0,
	IP_V6_ADDRESS_FAMILY = 1,
};

/* Socket communication type */
enum SocketType
{
	STREAM_SOCKET_TYPE = 0,
	DATAGRAM_SOCKET_TYPE = 1,
};

/* Socket connection shutdown */
enum SocketShutdown
{
	SHUTDOWN_RECEIVE_ONLY = 0,
	SHUTDOWN_SEND_ONLY = 1,
	SHUTDOWN_RECEIVE_SEND = 2,
};

/* Socket security protocol */
enum SecurityProtocol
{
	TLS_1_3_SECURITY_PROTOCOL = 0,
	DTLS_1_3_SECURITY_PROTOCOL = 1,
	TLS_1_2_SECURITY_PROTOCOL = 2,
	DTLS_1_2_SECURITY_PROTOCOL = 3,
	TLS_SECURITY_PROTOCOL = TLS_1_3_SECURITY_PROTOCOL,
	DTLS_SECURITY_PROTOCOL = DTLS_1_3_SECURITY_PROTOCOL,
};

/* Returns true if network was initialized. */
bool initializeNetwork();
/* Terminates network. */
void terminateNetwork();
/* Returns true if network is initialized */
bool isNetworkInitialized();

/*
 * Creates a new socket.
 * Returns socket on success, otherwise NULL.
 *
 * type - socket communication type.
 * family - internet protocol address family.
 * address - socket local bind address.
 * listening - socket listening state.
 * blocking - socket blocking mode.
 * sslContext - pointer to the SSL context or NULL.
 */
struct Socket* createSocket(
	uint8_t type,
	uint8_t family,
	const struct SocketAddress* address,
	bool listening,
	bool blocking,
	struct SslContext* sslContext);

/*
 * Destroys specified socket.
 * socket - pointer to the socket or NULL.
 */
void destroySocket(
	struct Socket* socket);

/*
 * Returns socket connection type.
 * socket - pointer to the valid socket.
 */
uint8_t getSocketType(
	const struct Socket* socket);

/*
 * Returns true if socket is in listening state.
 * socket - pointer to the valid socket.
 */
bool isSocketListening(
	const struct Socket* socket);

/*
 * Returns true if socket blocking mode.
 * socket - pointer to the valid socket.
 */
bool isSocketBlocking(
	const struct Socket* socket);

/*
 * Returns local socket address.
 * Returns true on success
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool getSocketLocalAddress(
	const struct Socket* socket,
	struct SocketAddress* address);

/*
 * Returns remote socket address.
 * Returns true on success
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool getSocketRemoteAddress(
	const struct Socket* socket,
	struct SocketAddress* address);

/*
 * Returns true if socket uses SSL.
 * socket - pointer to the valid socket.
 */
bool isSocketSsl(
	const struct Socket* socket);

/*
 * Returns socket SSL context.
 * socket - pointer to the valid socket.
 */
struct SslContext* getSocketSslContext(
	const struct Socket* socket);

/*
 * Returns true if socket in no delay mode.
 * socket - pointer to the valid socket.
 */
bool isSocketNoDelay(
	const struct Socket* socket);

/*
 * Sets socket no delay mode.
 * socket - pointer to the valid socket.
 */
void setSocketNoDelay(
	struct Socket* socket,
	bool value);

/*
 * Returns true if socket in reuse address mode.
 * socket - pointer to the valid socket.
 */
bool isSocketReuseAddress(
	const struct Socket* socket);

/*
 * Sets socket reuse address mode.
 * socket - pointer to the valid socket.
 */
void setSocketReuseAddress(
	struct Socket* socket,
	bool value);

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
	uint8_t type);

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
 * Receives socket message.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * buffer - pointer to the valid receive buffer.
 * size - message receive buffer size.
 * address - pointer to the valid address.
 * count - pointer to the valid receive byte count.
 */
bool socketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress* address,
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
 * Returns address on success, otherwise NULL.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 */
struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service);

/*
 * Resolves a new socket addresses.
 * Returns address on success, otherwise NULL.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 * family - socket address family.
 * type - socket connection type.
 */
struct SocketAddress* resolveSocketAddress(
	const char* host,
	const char* service,
	uint8_t family,
	uint8_t type);

/*
 * Destroys specified socket endpoint address.
 * address - pointer to the socket address or NULL.
 */
void destroySocketAddress(
	struct SocketAddress* address);

/*
 * Creates a new socket address copy.
 * Returns address on success, otherwise NULL.
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
uint8_t getSocketAddressFamily(
	const struct SocketAddress* address);

/*
 * Returns a new socket IP address byte array.
 * Returns IP address on success, otherwise NULL.
 *
 * address - pointer to the valid socket address.
 * size - pointer to the valid byte array size.
 */
uint8_t* getSocketAddressIP(
	const struct SocketAddress* address,
	size_t* size);

/*
 * Returns socket address port number.
 * address - pointer to the valid socket address.
 */
uint16_t getSocketAddressPort(
	const struct SocketAddress* address);

/* Returns maximum socket address host string length. */
size_t getSocketMaxHostLength();

/* Returns maximum socket address service string length. */
size_t getSocketMaxServiceLength();

/*
 * Returns socket address host name.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid socket host name.
 */
bool getSocketAddressHost(
	const struct SocketAddress* address,
	char* host);

/*
 * Returns socket address service name.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * service - pointer to the valid socket service name.
 */
bool getSocketAddressService(
	const struct SocketAddress* address,
	char* service);

/*
 * Returns socket address host and service name.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid host name string.
 * service - pointer to the valid host name string.
 */
bool getSocketAddressHostService(
	const struct SocketAddress* address,
	char* host,
	char* service);

/*
 * Creates a new SSL context.
 * Returns SSL context on success, otherwise NULL.
 *
 * socketType - target socket type value.
 * certificateVerifyPath - valid trusted certificates location.
 */
struct SslContext* createSslContext(
	uint8_t securityProtocol,
	const char* certificateVerifyPath);

/*
 * Creates a new SSL context.
 * Returns SSL context on success, otherwise NULL.
 *
 * socketType - target socket type value.
 * certificateFilePath - valid certificate file path string.
 * privateKeyFilePath - valid private key file path string.
 */
struct SslContext* createSslContextFromFile(
	uint8_t securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath);

/*
 * Destroys specified SSL context.
 * context - pointer to the SSL context or NULL.
 */
void destroySslContext(
	struct SslContext* context);

/*
 * Destroys SSL context security protocol.
 * context - pointer to the valid SSL context.
 */
uint8_t getSslContextSecurityProtocol(
	const struct SslContext* context);
