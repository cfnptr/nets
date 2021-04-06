#pragma once
#include "mpnw/defines.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#if __linux__
#include <byteswap.h>
#define swapBytes16(x) bswap_16(x)
#define swapBytes32(x) bswap_32(x)
#define swapBytes64(x) bswap_64(x)
#elif __APPLE__
#include <libkern/OSByteOrder.h>
#define swapBytes16(x) OSSwapInt16(x)
#define swapBytes32(x) OSSwapInt32(x)
#define swapBytes64(x) OSSwapInt64(x)
#elif _WIN32
#include <stdlib.h>
#define swapBytes16(x) _byteswap_ushort(x)
#define swapBytes32(x) _byteswap_ulong(x)
#define swapBytes64(x) _byteswap_uint64(x)
#endif

#if MPNW_IS_LITTLE_ENDIAN
#define hostToNet16(x) swapBytes16(x)
#define hostToNet32(x) swapBytes32(x)
#define hostToNet64(x) swapBytes64(x)
#define netToHost16(x) swapBytes16(x)
#define netToHost32(x) swapBytes32(x)
#define netToHost64(x) swapBytes64(x)
#else
#define hostToNet16(x) (x)
#define hostToNet32(x) (x)
#define hostToNet64(x) (x)
#define netToHost16(x) (x)
#define netToHost32(x) (x)
#define netToHost64(x) (x)
#endif

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

/* Maximum numeric host string length*/
#define MAX_NUMERIC_HOST_LENGTH 46
/* Maximum numeric service string length*/
#define MAX_NUMERIC_SERVICE_LENGTH 6

/* Socket instance handle */
typedef struct Socket Socket;
/* Socket address instance handle */
typedef struct SocketAddress SocketAddress;
/* Secure socket layer context handle */
typedef struct SslContext SslContext;

/* Socket internet protocol address family */
typedef enum ADDRESS_FAMILY_TYPE
{
	UNKNOWN_ADDRESS_FAMILY = 0,
	IP_V4_ADDRESS_FAMILY = 1,
	IP_V6_ADDRESS_FAMILY = 2,
} ADDRESS_FAMILY_TYPE;

/* Socket communication type */
typedef enum SOCKET_TYPE
{
	UNKNOWN_SOCKET_TYPE = 0,
	STREAM_SOCKET_TYPE = 1,
	DATAGRAM_SOCKET_TYPE = 2,
} SOCKET_TYPE;

/* Socket connection shutdown */
typedef enum SOCKET_SHUTDOWN
{
	SHUTDOWN_RECEIVE_ONLY = 0,
	SHUTDOWN_SEND_ONLY = 1,
	SHUTDOWN_RECEIVE_SEND = 2,
} SOCKET_SHUTDOWN;

/* Socket security protocol */
typedef enum SECURITY_PROTOCOL
{
	UNKNOWN_SECURITY_PROTOCOL = 0,
	TLS_SECURITY_PROTOCOL = 1,
	DTLS_SECURITY_PROTOCOL = 2,
	TLS_1_2_SECURITY_PROTOCOL = 3,
	DTLS_1_2_SECURITY_PROTOCOL = 4,
} SECURITY_PROTOCOL;

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
Socket* createSocket(
	uint8_t type,
	uint8_t family,
	const SocketAddress* address,
	bool listening,
	bool blocking,
	SslContext* sslContext);

/*
 * Destroys specified socket.
 * socket - pointer to the socket or NULL.
 */
void destroySocket(Socket* socket);

/*
 * Returns socket connection type.
 * socket - pointer to the valid socket.
 */
uint8_t getSocketType(const Socket* socket);

/*
 * Returns true if socket is in listening state.
 * socket - pointer to the valid socket.
 */
bool isSocketListening(const Socket* socket);

/*
 * Returns true if socket blocking mode.
 * socket - pointer to the valid socket.
 */
bool isSocketBlocking(const Socket* socket);

/*
 * Returns local socket address.
 * Returns true on success
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool getSocketLocalAddress(
	const Socket* socket,
	SocketAddress* address);

/*
 * Returns remote socket address.
 * Returns true on success
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool getSocketRemoteAddress(
	const Socket* socket,
	SocketAddress* address);

/*
 * Returns true if socket uses SSL.
 * socket - pointer to the valid socket.
 */
bool isSocketSsl(const Socket* socket);

/*
 * Returns socket SSL context.
 * socket - pointer to the valid socket.
 */
SslContext* getSocketSslContext(const Socket* socket);

/*
 * Returns true if socket in no delay mode.
 * socket - pointer to the valid socket.
 */
bool isSocketNoDelay(const Socket* socket);

/*
 * Sets socket no delay mode.
 * socket - pointer to the valid socket.
 */
void setSocketNoDelay(
	Socket* socket,
	bool value);

/*
 * Accepts a new socket connection.
 * Returns socket on success, otherwise NULL.
 *
 * socket - pointer to the valid socket.
 * timeoutTime - accept attempt timeout time.
 */
Socket* acceptSocket(Socket* socket);

/*
 * Accepts socket SSL connection.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 */
bool acceptSslSocket(Socket* socket);

/*
 * Connects socket to the specified address.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool connectSocket(
	Socket* socket,
	const SocketAddress* address);

/*
 * Connects socket SSL.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 */
bool connectSslSocket(Socket* socket);

/*
 * Shutdowns part of the full-duplex connection.
 *
 * socket - pointer to the valid socket.
 * type - socket connection shutdown.
 */
bool shutdownSocket(
	Socket* socket,
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
	Socket* socket,
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
	Socket* socket,
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
	Socket* socket,
	void* buffer,
	size_t size,
	SocketAddress* address,
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
	Socket* socket,
	const void* buffer,
	size_t count,
	const SocketAddress* address);

/*
 * Creates a new socket address.
 * Returns address on success, otherwise NULL.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 */
SocketAddress* createSocketAddress(
	const char* host,
	const char* service);

/*
 * Creates a new empty socket address.
 * Returns address on success, otherwise NULL.
 */
SocketAddress* createEmptySocketAddress();

/*
 * Resolves a new socket addresses.
 * Returns address on success, otherwise NULL.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 * family - socket address family.
 * type - socket connection type.
 */
SocketAddress* resolveSocketAddress(
	const char* host,
	const char* service,
	uint8_t family,
	uint8_t type);

/*
 * Destroys specified socket endpoint address.
 * address - pointer to the socket address or NULL.
 */
void destroySocketAddress(SocketAddress* address);

/*
 * Creates a new socket address copy.
 * Returns address on success, otherwise NULL.
 *
 * address - pointer to the valid socket address.
 */
SocketAddress* copySocketAddress(const SocketAddress* address);

/*
 * Compares two addresses.
 *
 * a - pointer to the valid socket address.
 * b - pointer to the valid socket address.
 */
int compareSocketAddress(
	const SocketAddress* a,
	const SocketAddress* b);

/*
 * Returns socket address family.
 * address - pointer to the valid socket address.
 */
uint8_t getSocketAddressFamily(const SocketAddress* address);

/*
 * Sets socket address family.
 *
 * address - pointer to the valid socket address.
 * addressFamily - socket address family.
 */
void setSocketAddressFamily(
	SocketAddress* address,
	uint8_t addressFamily);

/*
 * Returns socket address family IP byte array size.
 * addressFamily - socket address family.
 */
size_t getSocketAddressFamilyIpSize(uint8_t addressFamily);

/*
 * Returns socket IP address byte array size.
 * address - pointer to the valid socket address.
 */
size_t getSocketAddressIpSize(const SocketAddress* address);

/*
 * Returns socket IP address byte array.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * ip - pointer to the valid IP byte array.
 */
bool getSocketAddressIP(
	const SocketAddress* address,
	uint8_t* ip);

/*
 * Sets socket IP address byte array.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * ip - pointer to the valid IP byte array.
 * size - IP byte array size.
 */
bool setSocketAddressIP(
	SocketAddress* address,
	const uint8_t* ip,
	size_t size);

/*
 * Returns socket address port number.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * port - pointer to the valid socket address port.
 */
bool getSocketAddressPort(
	const SocketAddress* address,
	uint16_t* port);

/*
 * Sets socket address port number.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * port - socket address port.
 */
bool setSocketAddressPort(
	SocketAddress* address,
	uint16_t port);

/*
 * Returns socket address host name.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid socket host name.
 * length - host name string length.
 */
bool getSocketAddressHost(
	const SocketAddress* address,
	char* host,
	size_t length);

/*
 * Returns socket address service name.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * service - pointer to the valid socket service name.
 * length - service name string length.
 */
bool getSocketAddressService(
	const SocketAddress* address,
	char* service,
	size_t length);

/*
 * Returns socket address host and service name.
 * Returns true on successful get.
 *
 * address - pointer to the valid socket address.
 * host - pointer to the valid host name string.
 * hostLength - host name string length.
 * service - pointer to the valid host name string.
 * serviceLength - service name string length.
 */
bool getSocketAddressHostService(
	const SocketAddress* address,
	char* host,
	size_t hostLength,
	char* service,
	size_t serviceLength);

/*
 * Creates a new SSL context.
 * Returns SSL context on success, otherwise NULL.
 *
 * socketType - target socket type value.
 * certificateVerifyPath - valid trusted certificates location.
 */
SslContext* createSslContext(
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
SslContext* createSslContextFromFile(
	uint8_t securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain);

/*
 * Destroys specified SSL context.
 * context - pointer to the SSL context or NULL.
 */
void destroySslContext(SslContext* context);

/*
 * Destroys SSL context security protocol.
 * context - pointer to the valid SSL context.
 */
uint8_t getSslContextSecurityProtocol(
	const SslContext* context);
