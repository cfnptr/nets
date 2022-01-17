// Copyright 2020-2022 Nikita Fediuchin. All rights reserved.
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

#include "mpnw/socket.h"

#if __linux__ || __APPLE__
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_LENGTH socklen_t
#define closesocket(socket) close(socket)
#elif _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SOCKET_LENGTH int

static WSADATA wsaData;
#else
#error Unknown operating system
#endif

#if MPNW_SUPPORT_OPENSSL
#include "openssl/ssl.h"
#else
#define SSL_CTX void
#endif

struct Socket_T
{
	size_t queueSize;
	SOCKET handle;
	SocketType type;
	bool blocking;
#if MPNW_SUPPORT_OPENSSL
	uint8_t _alignment[2];
	SslContext sslContext;
	SSL* ssl;
#endif
};
struct SocketAddress_T
{
	struct sockaddr_storage handle;
};
struct SslContext_T
{
	SSL_CTX* handle;
};

static bool networkInitialized = false;

bool initializeNetwork()
{
	if (networkInitialized)
		return false;

#if _WIN32
	int result = WSAStartup(
		MAKEWORD(2,2),
		&wsaData);

	if (result != 0)
		return false;
#endif

#if MPNW_SUPPORT_OPENSSL
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
#endif

	networkInitialized = true;
	return true;
}
void terminateNetwork()
{
	if(!networkInitialized)
		return;

#if _WIN32
	int result = WSACleanup();

	if (result != 0)
		abort();
#endif

#if MPNW_SUPPORT_OPENSSL
	EVP_cleanup();
#endif

	networkInitialized = false;
}
bool isNetworkInitialized()
{
	return networkInitialized;
}

MpnwResult createSocket(
	SocketType socketType,
	AddressFamily addressFamily,
	SocketAddress socketAddress,
	bool blocking,
	SslContext sslContext,
	Socket* _socket)
{
	assert(socketType < SOCKET_TYPE_COUNT);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(socketAddress);
	assert(_socket);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

#if !MPNW_SUPPORT_OPENSSL
	assert(!sslContext);
#endif

	Socket socketInstance = malloc(
		sizeof(Socket_T));

	if (!socketInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	int type, protocol;

	if (socketType == STREAM_SOCKET_TYPE)
	{
		type = SOCK_STREAM;
		protocol = IPPROTO_TCP;
	}
	else if (socketType == DATAGRAM_SOCKET_TYPE)
	{
		type = SOCK_DGRAM;
		protocol = IPPROTO_UDP;
	}
	else
	{
		abort();
	}

	int family;
	SOCKET_LENGTH length;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		family = AF_INET;
		length = sizeof(struct sockaddr_in);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		family = AF_INET6;
		length = sizeof(struct sockaddr_in6);
	}
	else
	{
		abort();
	}

	SOCKET handle = socket(
		family,
		type,
		protocol);

	if (handle == INVALID_SOCKET)
	{
		free(socketInstance);
		return FAILED_TO_CREATE_SOCKET_MPNW_RESULT;
	}

	int result = bind(
		handle,
		(const struct sockaddr*)&socketAddress->handle,
		length);
	
	if (result != 0)
	{
		closesocket(handle);
		free(socketInstance);
		return FAILED_TO_BIND_SOCKET_MPNW_RESULT;
	}

	if (!blocking)
	{
#if __linux__ || __APPLE__
		int flags = fcntl(
			handle,
			F_GETFL,
			0);

		if (flags == -1)
		{
			closesocket(handle);
			free(socketInstance);
			return FAILED_TO_SET_SOCKET_FLAG_MPNW_RESULT;
		}

		result = fcntl(
			handle,
			F_SETFL,
			flags | O_NONBLOCK);
#elif _WIN32
		u_long flags = 1;

		result = ioctlsocket(
    		handle,
    		FIONBIO,
    		&flags);
#endif

		if (result != 0)
		{
			closesocket(handle);
			free(socketInstance);
			return FAILED_TO_SET_SOCKET_FLAG_MPNW_RESULT;
		}
	}

	socketInstance->queueSize = 0;
	socketInstance->handle = handle;
	socketInstance->type = socketType;
	socketInstance->blocking = blocking;

#if MPNW_SUPPORT_OPENSSL
	if (sslContext)
	{
		SSL* ssl = SSL_new(
			sslContext->handle);

		if (!ssl)
		{
			closesocket(handle);
			free(socketInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		result = SSL_set_fd(ssl, (int)handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(socketInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		socketInstance->sslContext = sslContext;
		socketInstance->ssl = ssl;
	}
	else
	{
		socketInstance->sslContext = NULL;
	}
#endif

	*_socket = socketInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroySocket(Socket socket)
{
	assert(networkInitialized);

	if (!socket)
		return;

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext)
		SSL_free(socket->ssl);
#endif

	int result = closesocket(
		socket->handle);

	if (result != 0)
		abort();

	free(socket);
}

SocketType getSocketType(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->type;
}
bool isSocketBlocking(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->blocking;
}
bool getSocketLocalAddress(
	Socket socket,
	SocketAddress socketAddress)
{
	assert(socket);
	assert(socketAddress);
	assert(networkInitialized);

	struct sockaddr_storage storage;

	memset(&storage, 0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getsockname(
		socket->handle,
		(struct sockaddr*)&storage,
		&length);

	if (result == 0)
	{
		socketAddress->handle = storage;
		return true;
	}
	else
	{
		return false;
	}
}
bool getSocketRemoteAddress(
	Socket socket,
	SocketAddress socketAddress)
{
	assert(socket);
	assert(socketAddress);
	assert(networkInitialized);

	struct sockaddr_storage storage;

	memset(&storage, 0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&storage,
		&length);

	if (result == 0)
	{
		socketAddress->handle = storage;
		return true;
	}
	else
	{
		return false;
	}
}
SslContext getSocketSslContext(Socket socket)
{
#if MPNW_SUPPORT_OPENSSL
	assert(socket);
	assert(networkInitialized);
	return socket->sslContext;
#else
	abort();
#endif
}

bool isSocketNoDelay(Socket socket)
{
	assert(socket);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);

#if __linux__ || __APPLE__
	int value;
#elif _WIN32
	BOOL value;
#endif

	SOCKET_LENGTH length;

	int result = getsockopt(
		socket->handle,
		IPPROTO_TCP,
		TCP_NODELAY,
		(char*)&value,
		&length);

	if (result != 0)
		abort();

#if __linux__ || __APPLE__
	return value != 0;
#elif _WIN32
	return value != FALSE;
#endif
}
void setSocketNoDelay(
	Socket socket,
	bool value)
{
	assert(socket);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);

#if __linux__ || __APPLE__
	int noDelay = value ? 1 : 0;
	SOCKET_LENGTH length = sizeof(int);
#elif _WIN32
	BOOL noDelay = value ? TRUE : FALSE;
	SOCKET_LENGTH length = sizeof(BOOL);
#endif

	int result = setsockopt(
		socket->handle,
		IPPROTO_TCP,
		TCP_NODELAY,
		(char*)&noDelay,
		length);

	if (result != 0)
		abort();
}

bool isSocketListening(Socket socket)
{
	assert(socket);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);
	return socket->queueSize > 0;
}
size_t getMaxSocketQueueSize()
{
	assert(networkInitialized);
	return SOMAXCONN;
}
size_t getSocketQueueSize(Socket socket)
{
	assert(socket);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);
	return socket->queueSize;
}

bool listenSocket(
	Socket socket,
	size_t queueSize)
{
	assert(socket);
	assert(queueSize > 0);
	assert(queueSize <= getMaxSocketQueueSize());
	assert(socket->queueSize == 0);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);

	int result = listen(
		socket->handle,
		(int)queueSize);

	if (result != 0)
		return false;

	socket->queueSize = queueSize;
	return true;
}
MpnwResult acceptSocket(
	Socket socket,
	Socket* accepted)
{
	assert(socket);
	assert(accepted);
	assert(socket->queueSize > 0);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);

	Socket acceptedInstance = malloc(
		sizeof(Socket_T));

	if (!acceptedInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	SOCKET handle = accept(
		socket->handle,
		NULL,
		0);

	if (handle == INVALID_SOCKET)
	{
		free(acceptedInstance);
		return FAILED_TO_ACCEPT_SOCKET_MPNW_RESULT;
	}

	if (!socket->blocking)
	{
#if __linux__ || __APPLE__
		int flags = fcntl(
			handle,
			F_GETFL,
			0);

		if (flags == -1)
		{
			closesocket(handle);
			free(acceptedInstance);
			return FAILED_TO_SET_SOCKET_FLAG_MPNW_RESULT;
		}

		int result = fcntl(
			handle,
			F_SETFL,
			flags | O_NONBLOCK);
#elif _WIN32
		u_long flags = 1;

		int result = ioctlsocket(
			handle,
			FIONBIO,
			&flags);
#endif

		if (result != 0)
		{
			closesocket(handle);
			free(acceptedInstance);
			return FAILED_TO_SET_SOCKET_FLAG_MPNW_RESULT;
		}
	}

	acceptedInstance->queueSize = 0;
	acceptedInstance->handle = handle;
	acceptedInstance->type = socket->type;
	acceptedInstance->blocking = socket->blocking;

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		SSL* ssl = SSL_new(
			socket->sslContext->handle);

		if (!ssl)
		{
			closesocket(handle);
			free(acceptedInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		int result = SSL_set_fd(
			ssl,
			(int)handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(acceptedInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		acceptedInstance->sslContext = socket->sslContext;
		acceptedInstance->ssl = ssl;
	}
	else
	{
		acceptedInstance->sslContext = NULL;
	}
#endif

	*accepted = acceptedInstance;
	return SUCCESS_MPNW_RESULT;
}

bool acceptSslSocket(Socket socket)
{
	assert(socket);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	assert(socket->sslContext);
	return SSL_accept(socket->ssl) == 1;
#else
	abort();
#endif
}

bool connectSocket(
	Socket socket,
	SocketAddress remoteAddress)
{
	assert(socket);
	assert(remoteAddress);
	assert(networkInitialized);

	int family = remoteAddress->handle.ss_family;

	SOCKET_LENGTH length;

	if (family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		abort();

	int result = connect(
		socket->handle,
		(const struct sockaddr*)&remoteAddress->handle,
		length);

	if (result == 0)
		return true;

#if __linux__ || __APPLE__
	return errno == EISCONN;
#elif _WIN32
	return WSAGetLastError() == WSAEISCONN;
#endif
}
bool connectSslSocket(Socket socket)
{
	assert(socket);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	assert(socket->sslContext);
	return SSL_connect(socket->ssl) == 1;
#else
	abort();
#endif
}

bool shutdownSocket(
	Socket socket,
	SocketShutdown _shutdown)
{
	assert(socket);
	assert(_shutdown < SOCKET_SHUTDOWN_COUNT);
	assert(networkInitialized);

	int type;

#if __linux__ || __APPLE__
	if (_shutdown == RECEIVE_ONLY_SOCKET_SHUTDOWN)
		type = SHUT_RD;
	else if (_shutdown == SEND_ONLY_SOCKET_SHUTDOWN)
		type = SHUT_WR;
	else if (_shutdown == RECEIVE_SEND_SOCKET_SHUTDOWN)
		type = SHUT_RDWR;
	else
		abort();
#elif _WIN32
	if (_shutdown == RECEIVE_ONLY_SOCKET_SHUTDOWN)
		type = SD_RECEIVE;
	else if (_shutdown == SEND_ONLY_SOCKET_SHUTDOWN)
		type = SD_SEND;
	else if (_shutdown == RECEIVE_SEND_SOCKET_SHUTDOWN)
		type = SD_BOTH;
	else
		abort();
#endif

	// Do not shutdown SSL, due to the bad documentation

	return shutdown(
		socket->handle,
		type) == 0;
}

bool socketReceive(
	Socket socket,
	void* receiveBuffer,
	size_t bufferSize,
	size_t* byteCount)
{
	assert(socket);
	assert(receiveBuffer);
	assert(bufferSize > 0);
	assert(byteCount);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		int result = SSL_read(
			socket->ssl,
			receiveBuffer,
			(int)bufferSize);

		if (result < 0)
			return false;

		*byteCount = (size_t)result;
		return true;
	}
#endif

	int64_t result = recv(
		socket->handle,
		(char*)receiveBuffer,
		(int)bufferSize,
		0);

	if (result < 0)
		return false;

	*byteCount = (size_t)result;
	return true;
}
bool socketSend(
	Socket socket,
	const void* sendBuffer,
	size_t byteCount)
{
	assert(socket);
	assert(sendBuffer);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		return SSL_write(
			socket->ssl,
			sendBuffer,
			(int)byteCount) == byteCount;
	}
#endif

	return send(
		socket->handle,
		(const char*)sendBuffer,
		(int)byteCount,
		0) == byteCount;
}
bool socketReceiveFrom(
	Socket socket,
	SocketAddress remoteAddress,
	void* receiveBuffer,
	size_t bufferSize,
	size_t* byteCount)
{
	assert(socket);
	assert(remoteAddress);
	assert(receiveBuffer);
	assert(bufferSize > 0);
	assert(byteCount);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	assert(!socket->sslContext);
#endif

	struct sockaddr_storage storage;

	memset(&storage, 0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int64_t count = recvfrom(
		socket->handle,
		(char*)receiveBuffer,
		(int)bufferSize,
		0,
		(struct sockaddr*)&storage,
		&length);

	if (count < 0)
		return false;

	remoteAddress->handle = storage;
	*byteCount = (size_t)count;
	return true;
}
bool socketSendTo(
	Socket socket,
	const void* sendBuffer,
	size_t byteCount,
	SocketAddress remoteAddress)
{
	assert(socket);
	assert(sendBuffer);
	assert(remoteAddress);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	assert(!socket->sslContext);
#endif

	int family = remoteAddress->handle.ss_family;

	SOCKET_LENGTH length;

	if (family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		abort();

	return sendto(
		socket->handle,
		(const char*)sendBuffer,
		(int)byteCount,
		0,
		(const struct sockaddr*)&remoteAddress->handle,
		length) == byteCount;
}

MpnwResult createSocketAddress(
	const char* host,
	const char* service,
	SocketAddress* socketAddress)
{
	assert(host);
	assert(service);
	assert(socketAddress);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

	SocketAddress socketAddressInstance = calloc(
		1, sizeof(SocketAddress_T));

	if (!socketAddressInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	struct addrinfo hints;

	memset(&hints, 0,
		sizeof(struct addrinfo));

	hints.ai_flags =
		AI_NUMERICHOST |
		AI_NUMERICSERV;

	struct addrinfo* addressInfos;

	int result = getaddrinfo(
		host,
		service,
		&hints,
		&addressInfos);

	if (result != 0)
	{
		free(socketAddressInstance);
		return FAILED_TO_GET_ADDRESS_INFO_MPNW_RESULT;
	}

	memcpy(&socketAddressInstance->handle,
		addressInfos->ai_addr,
		addressInfos->ai_addrlen);

	freeaddrinfo(addressInfos);

	*socketAddress = socketAddressInstance;
	return SUCCESS_MPNW_RESULT;
}
SocketAddress createSocketAddressCopy(
	SocketAddress socketAddress)
{
	assert(socketAddress);

	SocketAddress socketAddressInstance = malloc(
		sizeof(SocketAddress_T));

	if (!socketAddressInstance)
		return NULL;

	memcpy(socketAddressInstance,
		socketAddress,
		sizeof(SocketAddress_T));

	return socketAddressInstance;
}

MpnwResult resolveSocketAddress(
	const char* host,
	const char* service,
	AddressFamily family,
	SocketType type,
	SocketAddress* socketAddress)
{
	assert(host);
	assert(service);
	assert(family < ADDRESS_FAMILY_COUNT);
	assert(type < SOCKET_TYPE_COUNT);
	assert(socketAddress);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

	SocketAddress socketAddressInstance = calloc(
		1, sizeof(SocketAddress_T));

	if (!socketAddressInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	struct addrinfo hints;

	memset(&hints, 0,
		sizeof(struct addrinfo));

	hints.ai_flags =
		AI_ADDRCONFIG |
		AI_V4MAPPED;

	if (family == IP_V4_ADDRESS_FAMILY)
	{
		hints.ai_family = AF_INET;
	}
	else if (family == IP_V6_ADDRESS_FAMILY)
	{
		hints.ai_family = AF_INET6;
	}
	else
	{
		abort();
	}

	if (type == STREAM_SOCKET_TYPE)
	{
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
	else if (type == DATAGRAM_SOCKET_TYPE)
	{
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}
	else
	{
		abort();
	}

	struct addrinfo* addressInfos;

	int result = getaddrinfo(
		host,
		service,
		&hints,
		&addressInfos);

	if (result != 0)
	{
		free(socketAddressInstance);
		return FAILED_TO_GET_ADDRESS_INFO_MPNW_RESULT;
	}

	memcpy(&socketAddressInstance->handle,
		addressInfos->ai_addr,
		addressInfos->ai_addrlen);

	freeaddrinfo(addressInfos);

	*socketAddress = socketAddressInstance;
	return SUCCESS_MPNW_RESULT;
}

void destroySocketAddress(SocketAddress socketAddress)
{
	assert(networkInitialized);

	if (!socketAddress)
		return;

	free(socketAddress);
}

void copySocketAddress(
	SocketAddress sourceAddress,
	SocketAddress destinationAddress)
{
	assert(sourceAddress);
	assert(destinationAddress);

	memcpy(&destinationAddress->handle,
		&sourceAddress->handle,
		sizeof(struct sockaddr_storage));
}

int compareSocketAddress(
	SocketAddress a,
	SocketAddress b)
{
	// NOTE: a and b should not be NULL!
	// Skipping here assertions for debug build speed.

	int family = a->handle.ss_family;

	if (family == AF_INET)
	{
		return memcmp(
			&a->handle,
			&b->handle,
			sizeof(struct sockaddr_in));
	}
	if (family == AF_INET6)
	{
		return memcmp(
			&a->handle,
			&b->handle,
			sizeof(struct sockaddr_in6));
	}

	abort();
}

AddressFamily getSocketAddressFamily(
	SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;

	if (family == AF_INET)
		return IP_V4_ADDRESS_FAMILY;
	if (family == AF_INET6)
		return IP_V6_ADDRESS_FAMILY;

	abort();
}
size_t getSocketAddressFamilyIpSize(
	AddressFamily addressFamily)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(networkInitialized);

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
		return sizeof(struct in_addr);
	if (addressFamily == IP_V6_ADDRESS_FAMILY)
		return sizeof(struct in6_addr);

	abort();
}
size_t getSocketAddressIpSize(
	SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;

	if (family == AF_INET)
		return sizeof(struct in_addr);
	if (family == AF_INET6)
		return sizeof(struct in6_addr);

	abort();
}

const uint8_t* getSocketAddressIp(
	SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;

	if (family == AF_INET)
	{
		return (const uint8_t*)&((struct sockaddr_in*)
			&socketAddress->handle)->sin_addr;
	}
	if (family == AF_INET6)
	{
		return (const uint8_t*)&((struct sockaddr_in6*)
			&socketAddress->handle)->sin6_addr;
	}

	abort();
}
void setSocketAddressIp(
	SocketAddress socketAddress,
	const uint8_t* ip)
{
	assert(socketAddress);
	assert(ip);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;

	if (family == AF_INET)
	{
		memcpy(&((struct sockaddr_in*)&socketAddress->handle)->sin_addr,
			ip, sizeof(struct in_addr));
	}
	else if (family == AF_INET6)
	{
		memcpy(&((struct sockaddr_in6*)&socketAddress->handle)->sin6_addr,
			ip, sizeof(struct in6_addr));
	}
	else
	{
		abort();
	}
}

uint16_t getSocketAddressPort(
	SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&socketAddress->handle;
		return ntohs(address4->sin_port);
	}
	if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&socketAddress->handle;
		return ntohs(address6->sin6_port);
	}

	abort();
}
void setSocketAddressPort(
	SocketAddress socketAddress,
	uint16_t port)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&socketAddress->handle;
		address4->sin_port = htons(port);
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&socketAddress->handle;
		address6->sin6_port = htons(port);
	}
	else
	{
		abort();
	}
}

bool getSocketAddressHost(
	SocketAddress socketAddress,
	char* host,
	size_t length)
{
	assert(socketAddress);
	assert(host);
	assert(length > 0);
	assert(networkInitialized);

	int flags = NI_NUMERICHOST;

	return getnameinfo(
		(const struct sockaddr*)&socketAddress->handle,
		sizeof(struct sockaddr_storage),
		host,
		(SOCKET_LENGTH)length,
		NULL,
		0,
		flags) == 0;
}
bool getSocketAddressService(
	SocketAddress socketAddress,
	char* service,
	size_t length)
{
	assert(socketAddress);
	assert(service);
	assert(length > 0);
	assert(networkInitialized);

	int flags = NI_NUMERICSERV;

	return getnameinfo(
		(const struct sockaddr*)&socketAddress->handle,
		sizeof(struct sockaddr_storage),
		NULL,
		0,
		service,
		(SOCKET_LENGTH)length,
		flags) == 0;
}
bool getSocketAddressHostService(
	SocketAddress socketAddress,
	char* host,
	size_t hostLength,
	char* service,
	size_t serviceLength)
{
	assert(socketAddress);
	assert(host);
	assert(hostLength > 0);
	assert(service);
	assert(serviceLength > 0);
	assert(networkInitialized);

	int flags = NI_NUMERICHOST | NI_NUMERICSERV;

	return getnameinfo(
		(const struct sockaddr*)&socketAddress->handle,
		sizeof(struct sockaddr_storage),
		host,
		(SOCKET_LENGTH)hostLength,
		service,
		(SOCKET_LENGTH)serviceLength,
		flags) == 0;
}

MpnwResult createPublicSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* certificatesDirectory,
	SslContext* sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	assert(securityProtocol < SECURITY_PROTOCOL_COUNT);
	assert(sslContext);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

	SslContext sslContextInstance = malloc(
		sizeof(SslContext_T));

	if (!sslContextInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	SSL_CTX* handle;

	switch (securityProtocol)
	{
	default:
		abort();
	case TLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case TLS_1_2_SECURITY_PROTOCOL:
#if MPNW_SUPPORT_DEPRECATED_SSL
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
#else
		abort();
#endif

	}

	if (!handle)
	{
		free(sslContextInstance);
		return FAILED_TO_CREATE_SSL_MPNW_RESULT;
	}

	int result;

	if (certificateFilePath || certificatesDirectory)
	{
		result = SSL_CTX_load_verify_locations(
			handle,
			certificateFilePath,
			certificatesDirectory);
	}
	else
	{
		result = SSL_CTX_set_default_verify_paths(handle);
	}

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	sslContextInstance->handle = handle;

	*sslContext = sslContextInstance;
	return SUCCESS_MPNW_RESULT;
#else
	return NO_OPENSSL_SUPPORT_MPNW_RESULT;
#endif
}
MpnwResult createPrivateSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain,
	SslContext* sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	assert(securityProtocol < SECURITY_PROTOCOL_COUNT);
	assert(certificateFilePath);
	assert(privateKeyFilePath);
	assert(sslContext);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

	SslContext sslContextInstance = malloc(
		sizeof(SslContext_T));

	if (!sslContextInstance)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	SSL_CTX* handle;

	switch (securityProtocol)
	{
	default:
		abort();
	case TLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case TLS_1_2_SECURITY_PROTOCOL:
#if MPNW_SUPPORT_DEPRECATED_SSL
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
#else
		abort();
#endif
	}

	if (!handle)
	{
		free(sslContextInstance);
		return FAILED_TO_CREATE_SSL_MPNW_RESULT;
	}

	int result;

	if (certificateChain)
	{
		result = SSL_CTX_use_certificate_chain_file(
			handle,
			certificateFilePath);
	}
	else
	{
		result = SSL_CTX_use_certificate_file(
			handle,
			certificateFilePath,
			SSL_FILETYPE_PEM);
	}

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	result = SSL_CTX_use_PrivateKey_file(
		handle,
		privateKeyFilePath,
		SSL_FILETYPE_PEM);

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	result = SSL_CTX_check_private_key(handle);

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	sslContextInstance->handle = handle;

	*sslContext = sslContextInstance;
	return SUCCESS_MPNW_RESULT;
#else
	return NO_OPENSSL_SUPPORT_MPNW_RESULT;
#endif
}

void destroySslContext(SslContext sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	assert(networkInitialized);

	if (!sslContext)
		return;

	SSL_CTX_free(sslContext->handle);
	free(sslContext);
#else
	abort();
#endif
}

SecurityProtocol getSslContextSecurityProtocol(SslContext sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	assert(sslContext);
	assert(networkInitialized);

	const SSL_METHOD* method =
		SSL_CTX_get_ssl_method(sslContext->handle);

	if (method == TLS_method())
		return TLS_SECURITY_PROTOCOL;

#if MPNW_SUPPORT_DEPRECATED_SSL
	if (method == TLSv1_2_method())
		return TLS_1_2_SECURITY_PROTOCOL;
#endif

	abort();
#else
	abort();
#endif
}

bool sHandleStreamMessage(
	const uint8_t* receiveBuffer,
	size_t byteCount,
	uint8_t* messageBuffer,
	size_t messageBufferSize,
	size_t* messageByteCount,
	uint8_t messageLengthSize,
	bool(*receiveFunction)(const uint8_t*, size_t, void*),
	void* functionHandle)
{
	return handleStreamMessage(
		receiveBuffer,
		byteCount,
		messageBuffer,
		messageBufferSize,
		messageByteCount,
		messageLengthSize,
		receiveFunction,
		functionHandle);
}
