// Copyright 2020-2025 Nikita Fediuchin. All rights reserved.
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

/***********************************************************************************************************************
 * @file
 * @brief Network socket functions. (TCP, UDP)
 *
 * @details
 * A network socket is a a software abstraction that represents one endpoint of a two-way communication link between 
 * programs over a network. Typically identified by an IP address, a transport protocol (TCP, UDP), and a port number.
 **********************************************************************************************************************/

#pragma once
#include "nets/defines.h"

#include <string.h>
#include <stdbool.h>

#define ANY_IP_ADDRESS_V4 "0.0.0.0"        /**< Internet Protocol v4 any address. */
#define ANY_IP_ADDRESS_V6 "::"             /**< Internet Protocol v6 any address. */
#define LOOPBACK_IP_ADDRESS_V4 "127.0.0.1" /**< Internet protocol v4 loopback address. */
#define LOOPBACK_IP_ADDRESS_V6 "::1"       /**< Internet protocol v6 loopback address. */
#define LOCALHOST_HOSTNAME "localhost"     /**< Current computer IP address. */
#define ANY_IP_ADDRESS_SERVICE "0"         /**< System-allocated, dynamic port. */
#define MAX_NUMERIC_HOST_LENGTH 46         /**< Maximum numeric host string length. */
#define MAX_NUMERIC_SERVICE_LENGTH 6       /**< Maximum numeric service string length. */
#define IP_V4_SIZE 4                       /**< Internet Protocol v4 address size in bytes. */
#define IP_V6_SIZE 16                      /**< Internet Protocol v6 address size in bytes. */

typedef struct Socket_T Socket_T;               /**< Socket structure. */
typedef Socket_T* Socket;                       /**< Socket instance. */
typedef struct SocketAddress_T SocketAddress_T; /**< Socket IP address structure. */
typedef SocketAddress_T* SocketAddress;         /**< Socket IP address instance. */
typedef struct SslContext_T SslContext_T;       /**< Secure socket layer (SSL) context structure. */
typedef SslContext_T* SslContext;               /**< Secure socket layer (SSL) context instance. */

/**
 * @brief Socket internet protocol (IP) address family type.
 */
typedef enum SocketFamily_T
{
	IP_V4_SOCKET_FAMILY = 0, /**< IPv4 socket IP address family. (32-bit addresses) */
	IP_V6_SOCKET_FAMILY = 1, /**< IPv6 socket IP address family. (128-bit addresses) */
	SOCKET_FAMILY_COUNT = 2, /**< Socket internet protocol (IP) address family count. */
} SocketFamily_T;
typedef uint8_t SocketFamily; /**< Socket internet protocol (IP) address family type. */

/**
 * @brief Socket communication protocol type.
 */
typedef enum SocketType_T
{
	STREAM_SOCKET_TYPE = 0,   /**< Connection oriented, reliable, ordered byte stream. (TCP) */
	DATAGRAM_SOCKET_TYPE = 1, /**< Connectionless, unreliable, message oriented packets. (UDP) */
	SOCKET_TYPE_COUNT = 2,    /**< Socket communication protocol type count. */
} SocketType_T;
typedef uint8_t SocketType; /**< Socket communication protocol type. */

/**
 * @brief Socket connection shutdown mode.
 */
typedef enum SocketShutdown_T
{
	RECEIVE_ONLY_SOCKET_SHUTDOWN = 0, /**< Shutdowns only receive side of the socket. */
	SEND_ONLY_SOCKET_SHUTDOWN = 1,    /**< Shutdowns only send side of the socket. */
	RECEIVE_SEND_SOCKET_SHUTDOWN = 2, /**< Shutdowns both receive and send sides of the socket. */
	SOCKET_SHUTDOWN_COUNT = 3,        /**< Socket connection shutdown mode count. */
} SocketShutdown_T;
typedef uint8_t SocketShutdown; /**< Socket connection shutdown mode. */

/**
 * @brief Socket SSL security protocol type.
 */
typedef enum SslProtocol_T
{
	TLS_SECURITY_PROTOCOL = 0,     /**< Use highest supported TLS security protocol version. */
	TLS_1_2_SECURITY_PROTOCOL = 1, /**< Use TLS 1.2 security protocol version. */
	SSL_PROTOCOL_COUNT = 2,        /**< Socket SSL security protocol type count. */
} SslProtocol_T;
typedef uint8_t SslProtocol; /**< Socket SSL security protocol type. */

/***********************************************************************************************************************
 * @brief Initializes network subsystems.
 * @warning You should call this function before using sockets!
 * @return True on success, otherwise false.
 */
bool initializeNetwork();
/**
 * @brief Terminates network subsystems.
 */
void terminateNetwork();
/**
 * @brief Returns true if network subsystems are initialized.
 * @note You should initialize network before using sockets!
 */
bool isNetworkInitialized();

/**
 * @brief Disables SIGPIPE signal generation. (Linux only)
 */
void disableSigpipe();

/**
 * @brief Creates a new network socket instance.
 * @details Creates, initializes, and binds a new endpoint for network communication.
 * 
 * @note You should destroy created socket instance manually.
 *
 * @param type socket communication protocol type
 * @param family internet protocol address family
 * @param localAddress socket local bind address instance
 * @param isBlocking create socket in blocking mode
 * @param isOnlyIPv6 create socket in IPv6 only mode
 * @param sslContext socket SSL context instance or NULL
 * @param[out] socket pointer to the socket instance
 * 
 * @return The @ref NetsResult code and writes socket instance on success.
 */
NetsResult createSocket(SocketType type, SocketFamily family, SocketAddress localAddress,
	bool isBlocking, bool isOnlyIPv6, SslContext sslContext, Socket* socket);
/**
 * @brief Destroys network socket instance.
 * @param socket target socket instance or NULL
 */
void destroySocket(Socket socket);

/***********************************************************************************************************************
 * @brief Returns socket communication protocol type.
 * @param socket target socket instance
 */
SocketType getSocketType(Socket socket);
/**
 * @brief Returns socket internet protocol (IP) address family type.
 * @param socket target socket instance
 */
SocketFamily getSocketFamily(Socket socket);
/**
 * @brief Returns true if socket is in blocking mode.
 * @param socket target socket instance
 */
bool isSocketBlocking(Socket socket);
/**
 * @brief Returns true if IPv6 socket is not accepting IPv4 connections.
 * @param socket target socket instance
 */
bool isSocketOnlyIPv6(Socket socket);

/**
 * @brief Gets local socket IP address.
 * @return True on success, otherwise false.
 *
 * @param socket target socket instance
 * @param[out] socketAddress socket IP address instance
 */
bool getSocketLocalAddress(Socket socket, SocketAddress socketAddress);
/**
 * @brief Gets remote socket IP address.
 * @return True on success, otherwise false.
 *
 * @param socket target socket instance
 * @param[out] socketAddress socket IP address instance
 */
bool getSocketRemoteAddress(Socket socket, SocketAddress socketAddress);

/**
 * @brief Returns socket SSL context instance.
 * @param socket target socket instance
 */
SslContext getSocketSslContext(Socket socket);

/**
 * @brief Returns true if stream socket sends without caching.
 * @param socket target socket instance
 */
bool isSocketNoDelay(Socket socket);
/**
 * @brief Sets socket no delay mode.
 * @details Does stream socket sends without caching.
 *
 * @param socket target socket instance
 * @param value no delay mode value
 */
void setSocketNoDelay(Socket socket, bool value);

/**
 * @brief Returns true if socket is in the listening state.
 * @param socket target socket instance
 */
bool isSocketListening(Socket socket);
/**
 * @brief Returns maximum number of queued connections.
 */
size_t getMaxSocketQueueSize();
/**
 * @brief Returns socket pending connections queue size.
 * @param socket target socket instance
 */
size_t getSocketQueueSize(Socket socket);

/***********************************************************************************************************************
 * @brief Puts socket in a listening state.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param queueSize pending connections queue size
 */
NetsResult listenSocket(Socket socket, size_t queueSize);

/**
 * @brief Accepts a new socket connection.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param[out] accepted pointer to the accepted socket
 */
NetsResult acceptSocket(Socket socket, Socket* accepted);
/**
 * @brief Accepts socket SSL connection.
 * @return The operation @ref NetsResult code.
 * @param socket target socket instance
 */
NetsResult acceptSslSocket(Socket socket);

/**
 * @brief Connects socket to the specified remote address.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param remoteAddress remote socket IP address instance
 */
NetsResult connectSocket(Socket socket, SocketAddress remoteAddress);
/**
 * @brief Establishes socket SSL connection.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param[in] hostname remote socket SNI hostname or NULL
 */
NetsResult connectSslSocket(Socket socket, const char* hostname);

/**
 * @brief Shutdowns part of the full-duplex connection.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param shutdown socket connection shutdown mode
 */
NetsResult shutdownSocket(Socket socket, SocketShutdown shutdown);

/***********************************************************************************************************************
 * @brief Receives pending socket data.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param[out] receiveBuffer data receive buffer
 * @param bufferSize data receive buffer size in bytes
 * @param[out] byteCount pointer to the received byte count
 */
NetsResult socketReceive(Socket socket, void* receiveBuffer, size_t bufferSize, size_t* byteCount);
/**
 * @brief Sends specified data to the remote socket.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param[in] sendBuffer data send buffer
 * @param byteCount data byte count to send
 */
NetsResult socketSend(Socket socket, const void* sendBuffer, size_t byteCount);

/**
 * @brief Receives pending data from the remote socket.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param[out] remoteAddress remote socket IP address
 * @param[out] receiveBuffer data receive buffer
 * @param bufferSize data receive buffer size in bytes
 * @param[out] byteCount pointer to the received byte count
 */
NetsResult socketReceiveFrom(Socket socket, SocketAddress remoteAddress, 
	void* receiveBuffer, size_t bufferSize, size_t* byteCount);
/**
 * @brief Sends specified data to the remote socket.
 * @return The operation @ref NetsResult code.
 *
 * @param socket target socket instance
 * @param[in] sendBuffer data send buffer
 * @param byteCount data byte count to send
 * @param remoteAddress destination remote socket IP address
 */
NetsResult socketSendTo(Socket socket, const void* sendBuffer, size_t byteCount, SocketAddress remoteAddress);

// TODO: add async address resolve

/***********************************************************************************************************************
 * @brief Creates a new socket IP address instance.
 * @return The operation @ref NetsResult code.
 *
 * @param[in] host socket IP address host name string
 * @param[in] service socket IP address service name string (port)
 * @param[out] socketAddress pointer to the socket address instance
 */
NetsResult createSocketAddress(const char* host, const char* service, SocketAddress* socketAddress);
/**
 * @brief Creates a new any socket IP address instance.
 * @return The operation @ref NetsResult code.
 *
 * @param socketFamily socket IP address family type
 * @param[out] socketAddress pointer to the socket address instance
 */
NetsResult createAnySocketAddress(SocketFamily family, SocketAddress* socketAddress);

/**
 * @brief Create a new socket IP address copy instance.
 * @return A new socket address instance on success, otherwise NULL.
 * @param socketAddress target socket address instance to copy
 */
SocketAddress createSocketAddressCopy(SocketAddress socketAddress);
/**
 * @brief Destroys socket IP address instance.
 * @param socketAddress target socket address instance or NULL
 */
void destroySocketAddress(SocketAddress socketAddress);

/**
 * @brief Resolves a new socket IP address array.
 * @return The operation @ref NetsResult code.
 *
 * @param[in] host socket IP address host name string
 * @param[in] service socket IP address service name string (port)
 * @param family socket IP address family type
 * @param type socket communication protocol type
 * @param[out] socketAddresses pointer to the socket address array
 * @param[out] addressCount pointer to the socket address count
 */
NetsResult resolveSocketAddresses(const char* host, const char* service, SocketFamily family,
	SocketType type, SocketAddress** socketAddresses, size_t* addressCount);
/**
 * @brief Destroys resolved socket IP address array.
 *
 * @param[in] socketAddresses socket IP address array
 * @param addressCount socket address count
 */
void destroySocketAddresses(SocketAddress* socketAddresses, size_t addressCount);

/**
 * @brief Returns URL link parts location.
 *
 * @param[in] url uniform resource locator string
 * @param urlLength URL string length
 * @param[out] hostOffset pointer to the host part offset or NULL
 * @param[out] hostLength pointer to the host part length or NULL
 * @param[out] serviceOffset pointer to the service part offset or NULL
 * @param[out] serviceLength pointer to the service part length or NULL
 * @param[out] pathOffset pointer to the path part offset or NULL
 */
void getUrlParts(const char* url, size_t urlLength, size_t* hostOffset, size_t* hostLength,
	size_t* serviceOffset, size_t* serviceLength, size_t* pathOffset);
// TODO: also return username, and parse URI format

/***********************************************************************************************************************
 * @brief Copies source socket IP address to the destination.
 *
 * @param sourceAddress source socket address instance
 * @param destinationAddress destination socket address instance
 */
void copySocketAddress(SocketAddress sourceAddress, SocketAddress destinationAddress);
/**
 * @brief Compares two socket IP addresses.
 *
 * @param a first socket address instance
 * @param b second socket address instance
 */
int compareSocketAddress(SocketAddress a, SocketAddress b);

/**
 * @brief Returns socket IP address family type.
 * @param socketAddress target socket address instance
 */
SocketFamily getSocketAddressFamily(SocketAddress socketAddress);
/**
 * @brief Returns socket IP address family byte array size.
 * @param family socket IP address family type
 */
size_t getSocketFamilyIpSize(SocketFamily family);
/**
 * @brief Returns socket IP address byte array size.
 * @param socketAddress target socket address instance
 */
size_t getSocketAddressIpSize(SocketAddress socketAddress);

/**
 * @brief Returns socket IP address byte array.
 * @param socketAddress target socket address instance
 */
const uint8_t* getSocketAddressIP(SocketAddress socketAddress);
/**
 * @brief Sets socket IP address byte array.
 *
 * @param socketAddress target socket address instance
 * @param[in] ip socket IP address byte array
 */
void setSocketAddressIP(SocketAddress socketAddress, const uint8_t* ip);

/**
 * @brief Returns socket IP address port number.
 * @param socketAddress target socket address instance
 */
uint16_t getSocketAddressPort(SocketAddress socketAddress);
/**
 * @brief Sets socket IP address port number.
 *
 * @param socketAddress target socket address instance
 * @param port socket IP address port number
 */
void setSocketAddressPort(SocketAddress socketAddress, uint16_t port);

/***********************************************************************************************************************
 * @brief Resolves socket IP address host name. (Blocking call)
 * @warning This may be a slow running operation!
 * @return True on success, otherwise false.
 *
 * @param socketAddress target socket address instance
 * @param[out] host pointer to the host name string
 * @param length host name string length
 */
bool getSocketAddressHost(SocketAddress socketAddress, char* host, size_t length);
/**
 * @brief Resolves socket IP address service name. (Blocking call)
 * @warning This may be a slow running operation!
 * @return True on success, otherwise false.
 *
 * @param socketAddress target socket address instance
 * @param[out] service pointer to the service name string
 * @param length service name string length
 */
bool getSocketAddressService(SocketAddress socketAddress, char* service, size_t length);
/**
 * @brief Resolves socket IP address host and service name. (Blocking call!)
 * @warning This may be a slow running operation!
 * @return True on success, otherwise false.
 *
 * @param socketAddress target socket address instance
 * @param[out] host pointer to the host name string
 * @param hostLength host name string length
 * @param[out] service pointer to the service name string
 * @param serviceLength service name string length
 */
bool getSocketAddressHostService(SocketAddress socketAddress, char* host, 
	size_t hostLength, char* service, size_t serviceLength);

/**
 * @brief Create a new public socket SSL context.
 * @return The operation @ref NetsResult code.
 *
 * @param sslProtocol socket SSL security protocol type
 * @param[in] certificateFilePath certificate file path string or NULL
 * @param[in] certificatesDirectory certificates directory path string or NULL
 * @param[out] sslContext pointer to the SSL context instance
 */
NetsResult createPublicSslContext(SslProtocol sslProtocol, const char* certificateFilePath, 
	const char* certificatesDirectory, SslContext* sslContext);
/**
 * @brief Create a new private socket SSL context.
 * @return The operation @ref NetsResult code.
 *
 * @param sslProtocol socket SSL security protocol type
 * @param[in] certificateFilePath certificates file path string
 * @param[in] privateKeyFilePath private key file path string
 * @param certificateChain file path is certificate chain
 * @param[out] sslContext pointer to the SSL context instance
 */
NetsResult createPrivateSslContext(SslProtocol sslProtocol, const char* certificateFilePath, 
	const char* privateKeyFilePath, bool certificateChain, SslContext* sslContext);

/**
 * @brief Destroys socket SSL context instance.
 * @param sslContext target SSL context instance or NULL
 */
void destroySslContext(SslContext sslContext);

/**
 * @brief Returns socket SSL context security protocol type.
 * @param sslContext target SSL context instance
 */
SslProtocol getSslContextProtocol(SslContext sslContext);

/***********************************************************************************************************************
 * @brief Splits received stream data to the messages.
 * @return The operation @ref NetsResult code.
 *
 * @param[in] receiveBuffer received message buffer
 * @param byteCount message received byte count
 * @param[in,out] messageBuffer intermediate message buffer
 * @param messageBufferSize intermediate message buffer size
 * @param[in,out] messageByteCount pointer to the message buffer byte count
 * @param messageLengthSize message length header size
 * @param[in] receiveFunction pointer to the receive function
 * @param[in] functionHandle receive function handle or NULL
 */
inline static NetsResult handleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, 
	uint8_t* messageBuffer, size_t messageBufferSize, size_t* messageByteCount, uint8_t messageLengthSize, 
	NetsResult(*receiveFunction)(const uint8_t*, size_t, void*), void* functionHandle)
{
	assert(receiveBuffer);
	assert(messageBuffer);
	assert(messageBufferSize > 0);
	assert(messageByteCount);

	assert(messageLengthSize == sizeof(uint8_t) || messageLengthSize == sizeof(uint16_t) ||
		messageLengthSize == sizeof(uint32_t) || messageLengthSize == sizeof(uint64_t));
	assert(messageBufferSize >= messageLengthSize);

	if (byteCount == 0) // Check instead of assert for safety
		return CONNECTION_IS_CLOSED_NETS_RESULT;

	size_t _messageByteCount = *messageByteCount;
	size_t pointer = 0;
	
	if (_messageByteCount > 0) // Handle received data with buffered data
	{
		if (_messageByteCount < messageLengthSize) // Message buffer has not full size
		{
			size_t messageSizePart = (size_t)messageLengthSize - _messageByteCount;
			if (messageSizePart > byteCount) // Received not full message size
			{
				// Store part of the received message size
				memcpy(messageBuffer + _messageByteCount, receiveBuffer, byteCount * sizeof(uint8_t));
				*messageByteCount += byteCount;
				return SUCCESS_NETS_RESULT;
			}

			// Copy remaining message size part
			memcpy(messageBuffer + _messageByteCount, receiveBuffer, messageSizePart * sizeof(uint8_t));
			pointer += messageSizePart;
			_messageByteCount += messageSizePart;
		}

		
		uint64_t messageSize; // Decode received message size
		if (messageLengthSize == sizeof(uint8_t))
		{
			messageSize = messageBuffer[0];
		}
		else if (messageLengthSize == sizeof(uint16_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint16_t*)messageBuffer;
			#else
			datagramSize = swapBytes16(*(uint16_t*)datagramBuffer);
			#endif
		}
		else if (messageLengthSize == sizeof(uint32_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint32_t*)messageBuffer;
			#else
			datagramSize = swapBytes32(*(uint32_t*)datagramBuffer);
			#endif
		}
		else if (messageLengthSize == sizeof(uint64_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint64_t*)messageBuffer;
			#else
			datagramSize = swapBytes64(*(uint64_t*)datagramBuffer);
			#endif
		}
		else abort();

		if (messageSize > messageBufferSize - messageLengthSize)
			return OUT_OF_MEMORY_NETS_RESULT; // Received message is bigger than buffer

		size_t neededPartSize = messageSize - (_messageByteCount - messageLengthSize);
		if (neededPartSize > byteCount - pointer) 
		{
			size_t messagePartSize = byteCount - pointer;
			memcpy(messageBuffer + _messageByteCount,
				receiveBuffer + pointer, messagePartSize * sizeof(uint8_t));
			*messageByteCount = _messageByteCount + messagePartSize;
			return SUCCESS_NETS_RESULT; // Received not full message
		}

		memcpy(messageBuffer + _messageByteCount,
			receiveBuffer + pointer, neededPartSize * sizeof(uint8_t));

		NetsResult netsResult = receiveFunction(messageBuffer + 
			messageLengthSize, messageSize, functionHandle);
		if (netsResult != SUCCESS_NETS_RESULT)
			return netsResult;

		*messageByteCount = 0;
		pointer += neededPartSize;
	}

	
	while (pointer < byteCount) // Continue until all received data handled
	{
		if (messageLengthSize > byteCount - pointer)
		{
			size_t messageSizePart = byteCount - pointer;

			memcpy(messageBuffer, receiveBuffer + pointer,
				messageSizePart * sizeof(uint8_t));
			*messageByteCount += messageSizePart;
			return SUCCESS_NETS_RESULT; // Received not full message size
		}

		uint64_t messageSize; // Decode received message size
		if (messageLengthSize == sizeof(uint8_t))
		{
			messageSize = receiveBuffer[pointer];
		}
		else if (messageLengthSize == sizeof(uint16_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint16_t*)(receiveBuffer + pointer);
			#else
			datagramSize = swapBytes16(*(uint16_t*)(receiveBuffer + pointer));
			#endif
		}
		else if (messageLengthSize == sizeof(uint32_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint32_t*)(receiveBuffer + pointer);
			#else
			datagramSize = swapBytes32(*(uint32_t*)(receiveBuffer + pointer));
			#endif
		}
		else if (messageLengthSize == sizeof(uint64_t))
		{
			#if NETS_LITTLE_ENDIAN
			messageSize = *(uint64_t*)(receiveBuffer + pointer);
			#else
			datagramSize = swapBytes64(*(uint64_t*)(receiveBuffer + pointer));
			#endif
		}
		else abort();

		if (messageSize > messageBufferSize - messageLengthSize)
			return OUT_OF_MEMORY_NETS_RESULT; // Received message is bigger than buffer

		if (messageSize > (byteCount - pointer) - messageLengthSize)
		{
			size_t messagePartSize = byteCount - pointer;

			memcpy(messageBuffer, receiveBuffer + pointer,
				messagePartSize * sizeof(uint8_t));
			*messageByteCount += messagePartSize;
			return SUCCESS_NETS_RESULT; // Received not full message
		}

		// Handle received message data
		NetsResult netsResult = receiveFunction(receiveBuffer + pointer + 
			messageLengthSize, messageSize, functionHandle);
		if (netsResult != SUCCESS_NETS_RESULT)
			return netsResult;

		pointer += messageLengthSize + messageSize;
	}

	return SUCCESS_NETS_RESULT;
}

// For library symbols
NetsResult sHandleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, uint8_t* messageBuffer,
	size_t messageBufferSize, size_t* messageByteCount, uint8_t messageLengthSize,
	NetsResult(*receiveFunction)(const uint8_t*, size_t, void*), void* functionHandle);