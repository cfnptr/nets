#pragma once
#include "mpnw/defines.h"
#include "mpnw/byte_swap.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
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
	IP_V4_ADDRESS_FAMILY = 0,
	IP_V6_ADDRESS_FAMILY = 1,
	ADDRESS_FAMILY_COUNT = 2,
} AddressFamily;

/* Socket communication type */
typedef enum SocketType
{
	STREAM_SOCKET_TYPE = 0,
	DATAGRAM_SOCKET_TYPE = 1,
	SOCKET_TYPE_COUNT = 2,
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
	TLS_SECURITY_PROTOCOL = 0,
	TLS_1_2_SECURITY_PROTOCOL = 1,
	SECURITY_PROTOCOL_COUNT = 2,
} SecurityProtocol;

/*
 * Initialize network libraries.
 * Returns true on success.
 */
bool initializeNetwork();

/*
 * Terminate network libraries.
 */
void terminateNetwork();

/*
 * Returns true if network is initialized.
*/
bool isNetworkInitialized();

/*
 * Create a new socket instance.
 * Returns operation MPNW result.
 *
 * type - socket communication type.
 * family - internet protocol address family.
 * address - socket local bind address.
 * listening - socket listening state.
 * blocking - socket in blocking mode.
 * sslContext - SSL context or NULL.
 * socket - pointer to the socket value.
 */
MpnwResult createSocket(
	SocketType type,
	AddressFamily family,
	SocketAddress address,
	bool listening,
	bool blocking,
	SslContext sslContext,
	Socket* socket);

/*
 * Destroy socket instance.
 * socket - socket instance or NULL.
 */
void destroySocket(Socket socket);

/*
 * Returns socket connection type.
 * socket - socket instance.
 */
SocketType getSocketType(Socket socket);

/*
 * Returns true if socket is in listening state.
 * socket - socket instance.
 */
bool isSocketListening(Socket socket);

/*
 * Returns true if socket blocking mode.
 * socket - socket instance.
 */
bool isSocketBlocking(Socket socket);

/*
 * Get local socket address.
 * Returns true on success.
 *
 * socket - socket instance.
 * address - socket address instance.
 */
bool getSocketLocalAddress(
	Socket socket,
	SocketAddress address);

/*
 * Get remote socket address.
 * Returns true on success.
 *
 * socket - socket instance.
 * address - socket address instance.
 */
bool getSocketRemoteAddress(
	Socket socket,
	SocketAddress address);

/*
 * Returns true if socket uses SSL.
 * socket - socket instance.
 */
bool isSocketSsl(Socket socket);

/*
 * Returns socket SSL context.
 * socket - socket instance.
 */
SslContext getSocketSslContext(Socket socket);

/*
 * Returns true if socket is in no delay mode.
 * socket - socket instance.
 */
bool isSocketNoDelay(Socket socket);

/*
 * Set socket no delay mode.
 *
 * socket - socket instance.
 * value - no delay mode value.
 */
void setSocketNoDelay(
	Socket socket,
	bool value);

/*
 * Accept a new socket connection.
 * Returns operation MPNW result.
 *
 * socket - socket instance.
 * accepted - pointer to the accepted value.
 */
MpnwResult acceptSocket(
	Socket socket,
	Socket* accepted);

/*
 * Accept socket SSL connection.
 * Returns true on success.
 *
 * socket - socket instance.
 */
bool acceptSslSocket(Socket socket);

/*
 * Connect socket to the address.
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
	SocketShutdown type);

/*
 * Receive socket message.
 * Returns true on success.
 *
 * socket - socket instance.
 * buffer - message receive buffer.
 * size - message receive buffer size.
 * count - pointer to the count value.
 */
bool socketReceive(
	Socket socket,
	void* buffer,
	size_t size,
	size_t* count);

/*
 * Send socket message.
 * Returns true on success.
 *
 * socket - socket instance.
 * buffer - message send buffer.
 * count - send byte count.
 */
bool socketSend(
	Socket socket,
	const void* buffer,
	size_t count);

/*
 * Receive socket message from address.
 * Returns true on success.
 *
 * socket - socket instance.
 * address - remote socket address.
 * buffer - message receive buffer.
 * size - message receive buffer size.
 * count - pointer to the count value.
 */
bool socketReceiveFrom(
	Socket socket,
	SocketAddress address,
	void* buffer,
	size_t size,
	size_t* count);

/*
 * Send socket message to the address.
 * Returns true on success.
 *
 * socket - socket instance.
 * buffer - message send buffer.
 * count - message byte count to send.
 * address - remote socket address.
 */
bool socketSendTo(
	Socket socket,
	const void* buffer,
	size_t count,
	SocketAddress address);

/*
 * Create a new socket address.
 * Returns operation MPNW result.
 *
 * host - address host name string.
 * service - address service name string.
 * address - pointer to the address value.
 */
MpnwResult createSocketAddress(
	const char* host,
	const char* service,
	SocketAddress* address);

/*
 * Create a new socket address copy.
 * Returns address on success, otherwise NULL.
 *
 * address - socket address instance.
 */
SocketAddress createSocketAddressCopy(
	SocketAddress address);

/*
 * Resolve a new socket addresses.
 * Returns operation MPNW result.
 *
 * host - address host name string.
 * service - address service name string.
 * family - socket address family.
 * type - socket connection type.
 * address - pointer to the address value.
 */
MpnwResult resolveSocketAddress(
	const char* host,
	const char* service,
	AddressFamily family,
	SocketType type,
	SocketAddress* address);

/*
 * Destroy socket address instance.
 * address - socket address or NULL.
 */
void destroySocketAddress(SocketAddress address);

/*
 * Copy source socket address to the destination.
 *
 * sourceAddress - socket address instance.
 * destinationAddress - socket address instance.
 */
void copySocketAddress(
	SocketAddress sourceAddress,
	SocketAddress destinationAddress);

/*
 * Compare two addresses.
 *
 * a - socket address instance.
 * b - socket address instance.
 */
int compareSocketAddress(
	SocketAddress a,
	SocketAddress b);

/*
 * Returns socket address family.
 * address - socket address instance.
 */
AddressFamily getSocketAddressFamily(
	SocketAddress address);

/*
 * Set socket address family.
 *
 * address - socket address instance.
 * addressFamily - socket address family.
 */
void setSocketAddressFamily(
	SocketAddress address,
	AddressFamily addressFamily);

/*
 * Returns socket address family IP byte array size.
 * addressFamily - socket address family.
 */
size_t getSocketAddressFamilyIpSize(
	AddressFamily addressFamily);

/*
 * Returns socket IP address byte array size.
 * address - socket address instance.
 */
size_t getSocketAddressIpSize(
	SocketAddress address);

/*
 * Returns socket IP address byte array.
 *
 * address - socket address instance.
 * ip - pointer to the IP copy array.
 */
const uint8_t* getSocketAddressIp(
	SocketAddress address);

/*
 * Set socket IP address byte array.
 * Returns true on success.
 *
 * address - socket address instance.
 * ip - IP byte array.
 * size - IP byte array size.
 */
bool setSocketAddressIp(
	SocketAddress address,
	const uint8_t* ip,
	size_t size);

/*
 * Returns socket address port number.
 *
 * address - socket address instance.
 * port - pointer to the port value.
 */
uint16_t getSocketAddressPort(
	SocketAddress address);

/*
 * Set socket address port number.
 *
 * address - socket address instance.
 * port - socket address port.
 */
void setSocketAddressPort(
	SocketAddress address,
	uint16_t port);

/*
 * Get socket address host name.
 * Returns true on success.
 *
 * address - socket address instance.
 * host - pointer to the host name value.
 * length - host name string length.
 */
bool getSocketAddressHost(
	SocketAddress address,
	char* host,
	size_t length);

/*
 * Returns socket address service name.
 * Returns true on success.
 *
 * address - socket address instance.
 * service - pointer to the service name.
 * length - service name string length.
 */
bool getSocketAddressService(
	SocketAddress address,
	char* service,
	size_t length);

/*
 * Get socket address host and service name.
 * Returns true on success.
 *
 * address - socket address instance.
 * host - pointer to the host name.
 * hostLength - host name string length.
 * service - pointer to the service name.
 * serviceLength - service name string length.
 */
bool getSocketAddressHostService(
	SocketAddress address,
	char* host,
	size_t hostLength,
	char* service,
	size_t serviceLength);

/*
 * Create a new public SSL context.
 * Returns operation MPNW result.
 *
 * socketType - socket connection type.
 * certificateFilePath - certificate file path string or NULL.
 * certificatesDirectory - certificate's directory path string or NULL.
 * sslContext - pointer to the sslContext value.
 */
MpnwResult createPublicSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* certificatesDirectory,
	SslContext* sslContext);

/*
 * Creates a new private SSL context.
 * Returns operation MPNW result.
 *
 * socketType - target socket type value.
 * certificateFilePath - certificates file path string.
 * privateKeyFilePath - private key file path string.
 * certificateChain - file path is certificate chain.
 */
MpnwResult createPrivateSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain,
	SslContext* sslContext);

/*
 * Destroys SSL context instance.
 * context - SSL context instance or NULL.
 */
void destroySslContext(SslContext context);

/*
 * Returns SSL context security protocol.
 * context - SSL context instance.
 */
SecurityProtocol getSslContextSecurityProtocol(SslContext context);

/*
 * Splits and handles received stream data to the datagrams.
 * Returns true on all handle success
 *
 * receiveBuffer - message receive buffer.
 * byteCount - message received byte count.
 * datagramBuffer - receive datagram buffer.
 * datagramBufferSiz - receive datagram buffer size.
 * datagramByteCount - pointer to the datagram buffer byte count.
 * datagramLengthSize - datagram length header size.
 * receiveFunction - pointer to the receive handler.
 * functionHandle - receive function handle or NULL.
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
		{
			datagramSize = datagramBuffer[0];
		}
		else if (datagramLengthSize == sizeof(uint16_t))
		{
#if MPNW_LITTLE_ENDIAN
			datagramSize = *(uint16_t*)datagramBuffer;
#else
			datagramSize = swapBytes16(*(uint16_t*)datagramBuffer);
#endif
		}
		else if (datagramLengthSize == sizeof(uint32_t))
		{
#if MPNW_LITTLE_ENDIAN
			datagramSize = *(uint32_t*)datagramBuffer;
#else
			datagramSize = swapBytes32(*(uint32_t*)datagramBuffer);
#endif
		}
		else if (datagramLengthSize == sizeof(uint64_t))
		{
#if MPNW_LITTLE_ENDIAN
			datagramSize = *(uint64_t*)datagramBuffer;
#else
			datagramSize = swapBytes64(*(uint64_t*)datagramBuffer);
#endif
		}
		else
		{
			abort();
		}

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
		{
			datagramSize = receiveBuffer[pointer];
		}
		else if (datagramLengthSize == sizeof(uint16_t))
		{
#if MPNW_LITTLE_ENDIAN
			datagramSize = *(uint16_t*)(receiveBuffer + pointer);
#else
			datagramSize = swapBytes16(*(uint16_t*)(receiveBuffer + pointer));
#endif
		}
		else if (datagramLengthSize == sizeof(uint32_t))
		{
#if MPNW_LITTLE_ENDIAN
			datagramSize = *(uint32_t*)(receiveBuffer + pointer);
#else
			datagramSize = swapBytes32(*(uint32_t*)(receiveBuffer + pointer));
#endif
		}
		else if (datagramLengthSize == sizeof(uint64_t))
		{
#if MPNW_LITTLE_ENDIAN
			datagramSize = *(uint64_t*)(receiveBuffer + pointer);
#else
			datagramSize = swapBytes64(*(uint64_t*)(receiveBuffer + pointer));
#endif
		}
		else
		{
			abort();
		}

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
