// Copyright 2020-2021 Nikita Fediuchin. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include "mpnw/defines.h"

#include <string.h>
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
#define ANY_IP_ADDRESS_SERVICE "0"

/* Maximum numeric host string length*/
#define MAX_NUMERIC_HOST_LENGTH 46
/* Maximum numeric service string length*/
#define MAX_NUMERIC_SERVICE_LENGTH 6

/* IPv4 address size in bytes */
#define IP_V4_SIZE 4
/* IPv6 address size in bytes */
#define IP_V6_SIZE 16

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
 * socketType - socket communication type.
 * addressFamily - internet protocol address family.
 * socketAddress - socket local bind address.
 * blocking - socket in blocking mode.
 * sslContext - SSL context or NULL.
 * socket - pointer to the socket value.
 */
MpnwResult createSocket(
	SocketType socketType,
	AddressFamily addressFamily,
	SocketAddress socketAddress,
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
 * Returns true if socket blocking mode.
 * socket - socket instance.
 */
bool isSocketBlocking(Socket socket);

/*
 * Get local socket address.
 * Returns true on success.
 *
 * socket - socket instance.
 * socketAddress - socket address instance.
 */
bool getSocketLocalAddress(
	Socket socket,
	SocketAddress socketAddress);

/*
 * Get remote socket address.
 * Returns true on success.
 *
 * socket - socket instance.
 * socketAddress - socket address instance.
 */
bool getSocketRemoteAddress(
	Socket socket,
	SocketAddress socketAddress);

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
 * Returns true if socket is in listening state.
 * socket - socket instance.
 */
bool isSocketListening(Socket socket);

/*
 * Maximum number of queued connections.
 */
size_t getMaxSocketQueueSize();

/*
 * Returns socket pending connections queue size.
 * socket - socket instance.
 */
size_t getSocketQueueSize(Socket socket);

/*
 * Put socket in a listening state.
 *
 * socket - socket instance.
 * queueSize - pending connections queue size.
 */
bool listenSocket(
	Socket socket,
	size_t queueSize);

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
 * remoteAddress - pointer to the valid socket address.
 */
bool connectSocket(
	Socket socket,
	SocketAddress remoteAddress);

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
	SocketShutdown shutdown);

/*
 * Receive socket message.
 * Returns true on success.
 *
 * socket - socket instance.
 * receiveBuffer - message receive buffer.
 * bufferSize - message receive buffer size.
 * byteCount - pointer to the count value.
 */
bool socketReceive(
	Socket socket,
	void* receiveBuffer,
	size_t bufferSize,
	size_t* byteCount);

/*
 * Send socket message.
 * Returns true on success.
 *
 * socket - socket instance.
 * sendBuffer - message send buffer.
 * byteCount - send byte count.
 */
bool socketSend(
	Socket socket,
	const void* sendBuffer,
	size_t byteCount);

/*
 * Receive socket message from address.
 * Returns true on success.
 *
 * socket - socket instance.
 * remoteAddress - remote socket address.
 * receiveBuffer - message receive buffer.
 * bufferSize - message receive buffer size.
 * byteCount - pointer to the count value.
 */
bool socketReceiveFrom(
	Socket socket,
	SocketAddress remoteAddress,
	void* receiveBuffer,
	size_t bufferSize,
	size_t* byteCount);

/*
 * Send socket message to the address.
 * Returns true on success.
 *
 * socket - socket instance.
 * sendBuffer - message send buffer.
 * byteCount - message byte count to send.
 * socketAddress - remote socket address.
 */
bool socketSendTo(
	Socket socket,
	const void* sendBuffer,
	size_t byteCount,
	SocketAddress remoteAddress);

/*
 * Create a new socket address.
 * Returns operation MPNW result.
 *
 * host - address host name string.
 * service - address service name string.
 * socketAddress - pointer to the address value.
 */
MpnwResult createSocketAddress(
	const char* host,
	const char* service,
	SocketAddress* socketAddress);

/*
 * Create a new socket address copy.
 * Returns address on success, otherwise NULL.
 *
 * socketAddress - socket address instance.
 */
SocketAddress createSocketAddressCopy(
	SocketAddress socketAddress);

/*
 * Resolve a new socket addresses.
 * Returns operation MPNW result.
 *
 * host - address host name string.
 * service - address service name string.
 * family - socket address family.
 * type - socket connection type.
 * socketAddress - pointer to the address value.
 */
MpnwResult resolveSocketAddress(
	const char* host,
	const char* service,
	AddressFamily family,
	SocketType type,
	SocketAddress* socketAddress);

/*
 * Destroy socket address instance.
 * socketAddress - socket address or NULL.
 */
void destroySocketAddress(SocketAddress socketAddress);

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
 * socketAddress - socket address instance.
 */
AddressFamily getSocketAddressFamily(
	SocketAddress socketAddress);

/*
 * Returns socket address family IP byte array size.
 * addressFamily - socket address family.
 */
size_t getSocketAddressFamilyIpSize(
	AddressFamily addressFamily);

/*
 * Returns socket IP address byte array size.
 * socketAddress - socket address instance.
 */
size_t getSocketAddressIpSize(
	SocketAddress socketAddress);

/*
 * Returns socket IP address byte array.
 * socketAddress - socket address instance.
 */
const uint8_t* getSocketAddressIp(
	SocketAddress socketAddress);

/*
 * Set socket IP address byte array.
 *
 * socketAddress - socket address instance.
 * ip - IP byte array.
 */
void setSocketAddressIp(
	SocketAddress socketAddress,
	const uint8_t* ip);

/*
 * Returns socket address port number.
 * socketAddress - socket address instance.
 */
uint16_t getSocketAddressPort(
	SocketAddress socketAddress);

/*
 * Set socket address port number.
 *
 * socketAddress - socket address instance.
 * port - socket address port.
 */
void setSocketAddressPort(
	SocketAddress socketAddress,
	uint16_t port);

/*
 * Get socket address host name.
 * Returns true on success.
 *
 * socketAddress - socket address instance.
 * host - pointer to the host name value.
 * length - host name string length.
 */
bool getSocketAddressHost(
	SocketAddress socketAddress,
	char* host,
	size_t length);

/*
 * Returns socket address service name.
 * Returns true on success.
 *
 * socketAddress - socket address instance.
 * service - pointer to the service name.
 * length - service name string length.
 */
bool getSocketAddressService(
	SocketAddress socketAddress,
	char* service,
	size_t length);

/*
 * Get socket address host and service name.
 * Returns true on success.
 *
 * socketAddress - socket address instance.
 * host - pointer to the host name.
 * hostLength - host name string length.
 * service - pointer to the service name.
 * serviceLength - service name string length.
 */
bool getSocketAddressHostService(
	SocketAddress socketAddress,
	char* host,
	size_t hostLength,
	char* service,
	size_t serviceLength);

/*
 * Create a new public SSL context.
 * Returns operation MPNW result.
 *
 * securityProtocol - security protocol type.
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
 * securityProtocol - security protocol type.
 * certificateFilePath - certificates file path string.
 * privateKeyFilePath - private key file path string.
 * certificateChain - file path is certificate chain.
 * sslContext - pointer to the sslContext value.
 */
MpnwResult createPrivateSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain,
	SslContext* sslContext);

/*
 * Destroys SSL context instance.
 * sslContext - SSL context instance or NULL.
 */
void destroySslContext(SslContext sslContext);

/*
 * Returns SSL context security protocol.
 * sslContext - SSL context instance.
 */
SecurityProtocol getSslContextSecurityProtocol(SslContext sslContext);

/*
 * Splits and handles received stream data to the messages.
 * Returns true on all handle success
 *
 * receiveBuffer - message receive buffer.
 * byteCount - message received byte count.
 * messageBuffer - receive message buffer.
 * messageBufferSiz - receive message buffer size.
 * messageByteCount - pointer to the message buffer byte count.
 * messageLengthSize - message length header size.
 * receiveFunction - pointer to the receive handler.
 * functionHandle - receive function handle or NULL.
 */
inline static bool handleStreamMessage(
	const uint8_t* receiveBuffer,
	size_t byteCount,
	uint8_t* messageBuffer,
	size_t messageBufferSize,
	size_t* messageByteCount,
	uint8_t messageLengthSize,
	bool(*receiveFunction)(const uint8_t*, size_t, void*),
	void* functionHandle)
{
	assert(receiveBuffer != NULL);
	assert(messageBuffer != NULL);
	assert(messageBufferSize != 0);
	assert(messageByteCount != NULL);

	assert(
		messageLengthSize == sizeof(uint8_t) ||
		messageLengthSize == sizeof(uint16_t) ||
		messageLengthSize == sizeof(uint32_t) ||
		messageLengthSize == sizeof(uint64_t));
	assert(messageBufferSize >= messageLengthSize);

	// Check instead of assert for safety
	if (byteCount == 0)
		return false;

	size_t _messageByteCount = *messageByteCount;
	size_t pointer = 0;

	// Handle received data with buffered data
	if (_messageByteCount > 0)
	{
		// Message buffer has not full size
		if (_messageByteCount < messageLengthSize)
		{
			size_t messageSizePart = (size_t)
				messageLengthSize - _messageByteCount;

			// Received not full message size
			if (messageSizePart > byteCount)
			{
				// Store part of the received message size
				memcpy(
					messageBuffer + _messageByteCount,
					receiveBuffer,
					byteCount);
				*messageByteCount += byteCount;
				return true;
			}

			// Copy remaining message size part
			memcpy(
				messageBuffer + _messageByteCount,
				receiveBuffer,
				messageSizePart);
			pointer += messageSizePart;
			_messageByteCount += messageSizePart;
		}

		// Decode received message size
		uint64_t messageSize;

		if (messageLengthSize == sizeof(uint8_t))
		{
			messageSize = messageBuffer[0];
		}
		else if (messageLengthSize == sizeof(uint16_t))
		{
#if MPNW_LITTLE_ENDIAN
			messageSize = *(uint16_t*)messageBuffer;
#else
			datagramSize = swapBytes16(*(uint16_t*)datagramBuffer);
#endif
		}
		else if (messageLengthSize == sizeof(uint32_t))
		{
#if MPNW_LITTLE_ENDIAN
			messageSize = *(uint32_t*)messageBuffer;
#else
			datagramSize = swapBytes32(*(uint32_t*)datagramBuffer);
#endif
		}
		else if (messageLengthSize == sizeof(uint64_t))
		{
#if MPNW_LITTLE_ENDIAN
			messageSize = *(uint64_t*)messageBuffer;
#else
			datagramSize = swapBytes64(*(uint64_t*)datagramBuffer);
#endif
		}
		else
		{
			abort();
		}

		// Received message is bigger than buffer
		if (messageSize > messageBufferSize - messageLengthSize)
			return false;

		size_t neededPartSize = messageSize -
			(_messageByteCount - messageLengthSize);

		// Received not full message
		if (neededPartSize > byteCount - pointer)
		{
			size_t messagePartSize = byteCount - pointer;

			memcpy(
				messageBuffer + _messageByteCount,
				receiveBuffer + pointer,
				messagePartSize);
			*messageByteCount = _messageByteCount + messagePartSize;
			return true;
		}

		memcpy(
			messageBuffer + _messageByteCount,
			receiveBuffer + pointer,
			neededPartSize);

		bool result = receiveFunction(
			messageBuffer + messageLengthSize,
			messageSize,
			functionHandle);

		if (result == false)
			return false;

		*messageByteCount = 0;
		pointer += neededPartSize;
	}

	// Continue until all received data handled
	while (pointer < byteCount)
	{
		// Received not full message size
		if (messageLengthSize > byteCount - pointer)
		{
			size_t messageSizePart = byteCount - pointer;

			memcpy(
				messageBuffer,
				receiveBuffer + pointer,
				messageSizePart);
			*messageByteCount += messageSizePart;
			return true;
		}

		// Decode received message size
		uint64_t messageSize;

		if (messageLengthSize == sizeof(uint8_t))
		{
			messageSize = receiveBuffer[pointer];
		}
		else if (messageLengthSize == sizeof(uint16_t))
		{
#if MPNW_LITTLE_ENDIAN
			messageSize = *(uint16_t*)(receiveBuffer + pointer);
#else
			datagramSize = swapBytes16(*(uint16_t*)(receiveBuffer + pointer));
#endif
		}
		else if (messageLengthSize == sizeof(uint32_t))
		{
#if MPNW_LITTLE_ENDIAN
			messageSize = *(uint32_t*)(receiveBuffer + pointer);
#else
			datagramSize = swapBytes32(*(uint32_t*)(receiveBuffer + pointer));
#endif
		}
		else if (messageLengthSize == sizeof(uint64_t))
		{
#if MPNW_LITTLE_ENDIAN
			messageSize = *(uint64_t*)(receiveBuffer + pointer);
#else
			datagramSize = swapBytes64(*(uint64_t*)(receiveBuffer + pointer));
#endif
		}
		else
		{
			abort();
		}

		// Received message is bigger than buffer
		if (messageSize > messageBufferSize - messageLengthSize)
			return false;

		// Received not full message
		if (messageSize > (byteCount - pointer) - messageLengthSize)
		{
			size_t messagePartSize = byteCount - pointer;

			memcpy(
				messageBuffer,
				receiveBuffer + pointer,
				messagePartSize);
			*messageByteCount += messagePartSize;
			return true;
		}

		// Handle received message data
		bool result = receiveFunction(
			receiveBuffer + pointer + messageLengthSize,
			messageSize,
			functionHandle);

		if (result == false)
			return false;

		pointer += messageLengthSize + messageSize;
	}

	return true;
}

// For library symbols
bool sHandleStreamMessage(
	const uint8_t* receiveBuffer,
	size_t byteCount,
	uint8_t* messageBuffer,
	size_t messageBufferSize,
	size_t* messageByteCount,
	size_t messageLengthSize,
	bool(*receiveFunction)(const uint8_t*, size_t, void*),
	void* functionHandle);
