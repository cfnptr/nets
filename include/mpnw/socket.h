#pragma once
#include "mpnw/defines.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
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

#if MPNW_LITTLE_ENDIAN
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
typedef struct Socket* Socket;
/* Socket address instance handle */
typedef struct SocketAddress* SocketAddress;
/* Secure socket layer context handle */
typedef struct SslContext* SslContext;

/* Socket internet protocol address family */
typedef enum AddressFamily
{
	UNKNOWN_ADDRESS_FAMILY = 0,
	IP_V4_ADDRESS_FAMILY = 1,
	IP_V6_ADDRESS_FAMILY = 2,
	ADDRESS_FAMILY_COUNT = 3,
} AddressFamily;

/* Socket communication type */
typedef enum SocketType
{
	UNKNOWN_SOCKET_TYPE = 0,
	STREAM_SOCKET_TYPE = 1,
	DATAGRAM_SOCKET_TYPE = 2,
	SOCKET_TYPE_COUNT = 3,
} SocketType;

/* Socket connection shutdown */
typedef enum SocketShutdown
{
	RECEIVE_ONLY_SOCKET_SHUTDOWN = 0,
	SEND_ONLY_SOCKET_SHUTDOWN = 1,
	RECEIVE_SEND_SOCKET_SHUTDOWN = 2,
	SOCKET_SHUTDOWN_COUNT = 3,
} SocketShutdown;

/* Socket security protocol */
typedef enum SecurityProtocol
{
	UNKNOWN_SECURITY_PROTOCOL = 0,
	TLS_SECURITY_PROTOCOL = 1,
	TLS_1_2_SECURITY_PROTOCOL = 2,
	SECURITY_PROTOCOL_COUNT = 3,
} SecurityProtocol;

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
Socket createSocket(
	uint8_t type,
	uint8_t family,
	SocketAddress address,
	bool listening,
	bool blocking,
	SslContext sslContext);

/*
 * Destroys specified socket.
 * socket - pointer to the socket or NULL.
 */
void destroySocket(Socket socket);

/*
 * Returns socket connection type.
 * socket - pointer to the valid socket.
 */
uint8_t getSocketType(Socket socket);

/*
 * Returns true if socket is in listening state.
 * socket - pointer to the valid socket.
 */
bool isSocketListening(Socket socket);

/*
 * Returns true if socket blocking mode.
 * socket - pointer to the valid socket.
 */
bool isSocketBlocking(Socket socket);

/*
 * Returns local socket address.
 * Returns true on success
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool getSocketLocalAddress(
	Socket socket,
	SocketAddress address);

/*
 * Returns remote socket address.
 * Returns true on success
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool getSocketRemoteAddress(
	Socket socket,
	SocketAddress address);

/*
 * Returns true if socket uses SSL.
 * socket - pointer to the valid socket.
 */
bool isSocketSsl(Socket socket);

/*
 * Returns socket SSL context.
 * socket - pointer to the valid socket.
 */
SslContext getSocketSslContext(Socket socket);

/*
 * Returns true if socket in no delay mode.
 * socket - pointer to the valid socket.
 */
bool isSocketNoDelay(Socket socket);

/*
 * Sets socket no delay mode.
 * socket - pointer to the valid socket.
 * value - no delay mode value.
 */
void setSocketNoDelay(
	Socket socket,
	bool value);

/*
 * Accepts a new socket connection.
 * Returns socket on success, otherwise NULL.
 *
 * socket - pointer to the valid socket.
 * timeoutTime - accept attempt timeout time.
 */
Socket acceptSocket(Socket socket);

/*
 * Accepts socket SSL connection.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 */
bool acceptSslSocket(Socket socket);

/*
 * Connects socket to the specified address.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid socket address.
 */
bool connectSocket(
	Socket socket,
	SocketAddress address);

/*
 * Connects socket SSL.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 */
bool connectSslSocket(Socket socket);

/*
 * Shutdowns part of the full-duplex connection.
 *
 * socket - pointer to the valid socket.
 * type - socket connection shutdown.
 */
bool shutdownSocket(
	Socket socket,
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
	Socket socket,
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
	Socket socket,
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
	Socket socket,
	void* buffer,
	size_t size,
	SocketAddress address,
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
	Socket socket,
	const void* buffer,
	size_t count,
	SocketAddress address);

/*
 * Creates a new socket address.
 * Returns address on success, otherwise NULL.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 */
SocketAddress createSocketAddress(
	const char* host,
	const char* service);

/*
 * Creates a new empty socket address.
 * Returns address on success, otherwise NULL.
 */
SocketAddress createEmptySocketAddress();

/*
 * Creates a new socket address copy.
 * Returns address on success, otherwise NULL.
 *
 * address - pointer to the valid socket address.
 */
SocketAddress createSocketAddressCopy(SocketAddress address);

/*
 * Resolves a new socket addresses.
 * Returns address on success, otherwise NULL.
 *
 * host - pointer to the valid host name.
 * service - pointer to the valid service name.
 * family - socket address family.
 * type - socket connection type.
 */
SocketAddress resolveSocketAddress(
	const char* host,
	const char* service,
	uint8_t family,
	uint8_t type);

/*
 * Destroys specified socket endpoint address.
 * address - pointer to the socket address or NULL.
 */
void destroySocketAddress(SocketAddress address);

/*
 * Copies source socket address to the destination.
 *
 * sourceAddress - pointer to the valid socket address.
 * destinationAddress - pointer to the valid socket address.
 */
void copySocketAddress(
	SocketAddress sourceAddress,
	SocketAddress destinationAddress);

/*
 * Compares two addresses.
 *
 * a - pointer to the valid socket address.
 * b - pointer to the valid socket address.
 */
int compareSocketAddress(
	SocketAddress a,
	SocketAddress b);

/*
 * Returns socket address family.
 * address - pointer to the valid socket address.
 */
uint8_t getSocketAddressFamily(SocketAddress address);

/*
 * Sets socket address family.
 *
 * address - pointer to the valid socket address.
 * addressFamily - socket address family.
 */
void setSocketAddressFamily(
	SocketAddress address,
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
size_t getSocketAddressIpSize(SocketAddress address);

/*
 * Returns socket IP address byte array.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * ip - pointer to the valid IP byte array.
 */
bool getSocketAddressIp(
	SocketAddress address,
	uint8_t* ip);

/*
 * Sets socket IP address byte array.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * ip - pointer to the valid IP byte array.
 * size - IP byte array size.
 */
bool setSocketAddressIp(
	SocketAddress address,
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
	SocketAddress address,
	uint16_t* port);

/*
 * Sets socket address port number.
 * Returns true on success.
 *
 * address - pointer to the valid socket address.
 * port - socket address port.
 */
bool setSocketAddressPort(
	SocketAddress address,
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
	SocketAddress address,
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
	SocketAddress address,
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
	SocketAddress address,
	char* host,
	size_t hostLength,
	char* service,
	size_t serviceLength);

/*
 * Creates a new public SSL context.
 * Returns SSL context on success, otherwise NULL.
 *
 * socketType - target socket type value.
 * certificateFilePath - certificate file path string.
 * certificatesDirectory - certificate's directory path string.
 */
SslContext createPublicSslContext(
	uint8_t securityProtocol,
	const char* certificateFilePath,
	const char* certificatesDirectory);

/*
 * Creates a new private SSL context.
 * Returns SSL context on success, otherwise NULL.
 *
 * socketType - target socket type value.
 * certificateFilePath - certificates file path string.
 * privateKeyFilePath - private key file path string.
 * certificateChain - file path is certificate chain.
 */
SslContext createPrivateSslContext(
	uint8_t securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain);

/*
 * Destroys specified SSL context.
 * context - pointer to the SSL context or NULL.
 */
void destroySslContext(SslContext context);

/*
 * Destroys SSL context security protocol.
 * context - pointer to the valid SSL context.
 */
uint8_t getSslContextSecurityProtocol(SslContext context);

/*
 * Splits and handles received stream data to the datagrams.
 * Returns true on all handle success
 *
 * receiveBuffer - pointer to the valid receive buffer.
 * byteCount - receive buffer byte count.
 * datagramBuffer - pointer to the valid datagram buffer.
 * datagramByteCount - pointer to the valid datagram buffer byte count.
 * datagramLengthSize - datagram length header size.
 * receiveFunction - pointer to the valid receive handler.
 * functionHandle - pointer to the function handle or NULL.
 */
inline static bool handleStreamDatagram(
	const uint8_t* receiveBuffer,
	size_t byteCount,
	uint8_t* datagramBuffer,
	size_t datagramBufferSize,
	size_t* datagramByteCount,
	size_t datagramLengthSize,
	bool(*receiveFunction)(const uint8_t*, size_t, void*),
	void* functionHandle)
{
	assert(receiveBuffer != NULL);
	assert(byteCount != 0);
	assert(datagramBuffer != NULL);
	assert(datagramBufferSize != 0);
	assert(datagramByteCount != NULL);

	assert(
		datagramLengthSize == sizeof(uint8_t) ||
		datagramLengthSize == sizeof(uint16_t) ||
		datagramLengthSize == sizeof(uint32_t) ||
		datagramLengthSize == sizeof(uint64_t));
	assert(datagramBufferSize >= datagramLengthSize);

	size_t _datagramByteCount =
		*datagramByteCount;

	size_t pointer = 0;

	// Handle received data with buffered data
	if (_datagramByteCount > 0)
	{
		// Datagram buffer has not full size
		if (_datagramByteCount < datagramLengthSize)
		{
			size_t datagramSizePart =
				datagramLengthSize - _datagramByteCount;

			// Received not full datagram size
			if (datagramSizePart > byteCount)
			{
				// Store part of the received datagram size
				memcpy(
					datagramBuffer + _datagramByteCount,
					receiveBuffer,
					byteCount);
				*datagramByteCount += byteCount;
				return true;
			}

			// Copy remaining datagram size part
			memcpy(
				datagramBuffer + _datagramByteCount,
				receiveBuffer,
				datagramSizePart);
			pointer += datagramSizePart;
			_datagramByteCount += datagramSizePart;
		}

		// Decode received datagram size
		uint64_t datagramSize;

		if (datagramLengthSize == sizeof(uint8_t))
			datagramSize = datagramBuffer[0];
		else if (datagramLengthSize == sizeof(uint16_t))
			datagramSize = netToHost16(*(uint16_t*)datagramBuffer);
		else if (datagramLengthSize == sizeof(uint32_t))
			datagramSize = netToHost32(*(uint32_t*)datagramBuffer);
		else if (datagramLengthSize == sizeof(uint64_t))
			datagramSize = netToHost64(*(uint64_t*)datagramBuffer);
		else
			abort();

		// Received datagram is bigger than buffer
		if (datagramSize > datagramBufferSize - datagramLengthSize)
			return false;

		size_t neededPartSize = datagramSize -
			(_datagramByteCount - datagramLengthSize);

		// Received not full datagram
		if (neededPartSize > byteCount - pointer)
		{
			size_t datagramPartSize = byteCount - pointer;

			memcpy(
				datagramBuffer + _datagramByteCount,
				receiveBuffer + pointer,
				datagramPartSize);
			*datagramByteCount = _datagramByteCount + datagramPartSize;
			return true;
		}

		memcpy(
			datagramBuffer + _datagramByteCount,
			receiveBuffer + pointer,
			neededPartSize);

		bool result = receiveFunction(
			datagramBuffer + datagramLengthSize,
			datagramSize,
			functionHandle);

		if (result == false)
			return false;

		*datagramByteCount = 0;
		pointer += neededPartSize;
	}

	// Continue until all received data handled
	while (pointer < byteCount)
	{
		// Received not full datagram size
		if (datagramLengthSize > byteCount - pointer)
		{
			size_t datagramSizePart = byteCount - pointer;

			memcpy(
				datagramBuffer,
				receiveBuffer + pointer,
				datagramSizePart);
			*datagramByteCount += datagramSizePart;
			return true;
		}

		// Decode received datagram size
		uint64_t datagramSize;

		if (datagramLengthSize == sizeof(uint8_t))
			datagramSize = receiveBuffer[pointer];
		else if (datagramLengthSize == sizeof(uint16_t))
			datagramSize = netToHost16(*(uint16_t*)(receiveBuffer + pointer));
		else if (datagramLengthSize == sizeof(uint32_t))
			datagramSize = netToHost32(*(uint32_t*)(receiveBuffer + pointer));
		else if (datagramLengthSize == sizeof(uint64_t))
			datagramSize = netToHost64(*(uint64_t*)(receiveBuffer + pointer));
		else
			abort();

		// Received datagram is bigger than buffer
		if (datagramSize > datagramBufferSize - datagramLengthSize)
			return false;

		// Received not full datagram
		if (datagramSize > (byteCount - pointer) - datagramLengthSize)
		{
			size_t datagramPartSize = byteCount - pointer;

			memcpy(
				datagramBuffer,
				receiveBuffer + pointer,
				datagramPartSize);
			*datagramByteCount += datagramPartSize;
			return true;
		}

		// Handle received datagram data
		bool result = receiveFunction(
			receiveBuffer + pointer + datagramLengthSize,
			datagramSize,
			functionHandle);

		if (result == false)
			return false;

		pointer += datagramLengthSize + datagramSize;
	}

	return true;
}
