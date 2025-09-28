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

#include "nets/socket.h"

#if __linux__ || __APPLE__
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
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

#if NETS_SUPPORT_OPENSSL
#include "openssl/ssl.h"
#else
#define SSL_CTX void
#endif

struct Socket_T
{
	size_t queueSize;
	SOCKET handle;
	SocketType type;
	SocketFamily family;
	bool isBlocking;
	bool isOnlyIPv6;
	#if NETS_SUPPORT_OPENSSL
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

//**********************************************************************************************************************
static bool networkInitialized = false;

bool initializeNetwork()
{
	if (networkInitialized)
		return false;

	#if _WIN32
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return false;
	#endif

	networkInitialized = true;
	return true;
}
void terminateNetwork()
{
	if(!networkInitialized)
		return;

	#if _WIN32
	if (WSACleanup() != 0)
		abort(); // Note: network subsystem failure.
	#endif

	networkInitialized = false;
}
bool isNetworkInitialized()
{
	return networkInitialized;
}

//**********************************************************************************************************************
inline static NetsResult errorToNetsResult(int error)
{
	#if __linux__ || __APPLE__
	switch (error)
	{
	default:
		return UNKNOWN_ERROR_NETS_RESULT;
	case EALREADY:
	case EINPROGRESS:
	case EWOULDBLOCK:
		return IN_PROGRESS_NETS_RESULT;
	case EAFNOSUPPORT:
	case EPROTONOSUPPORT:
	case ESOCKTNOSUPPORT:
	case EOPNOTSUPP:
		return NOT_SUPPORTED_NETS_RESULT;
	case EMFILE:
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	case ENOBUFS:
	case ENOMEM:
		return OUT_OF_MEMORY_NETS_RESULT;
	case EACCES:
	case EPERM:
		return NO_ACCESS_NETS_RESULT;
	case EADDRINUSE:
		return ADDRESS_IS_ALREADY_IN_USE_NETS_RESULT;
	case EADDRNOTAVAIL:
		return BAD_ADDRESS_NETS_RESULT;
	case EINVAL:
	case EFAULT:
	case ENOTSOCK:
	case EBADF:
		return BAD_DATA_NETS_RESULT;
	case EISCONN:
		return ALREADY_CONNECTED_NETS_RESULT;
	case ECONNREFUSED:
		return CONNECTION_IS_REFUSED_NETS_RESULT;
	case ECONNABORTED:
		return CONNECTION_IS_ABORTED_NETS_RESULT;
	case ECONNRESET:
		return CONNECTION_IS_RESET_NETS_RESULT;
	case EPIPE:
		return CONNECTION_IS_CLOSED_NETS_RESULT;
	case ENETUNREACH:
		return NETWORK_IS_NOT_REACHABLE_NETS_RESULT;
	case EHOSTUNREACH:
		return HOST_IS_NOT_REACHABLE_NETS_RESULT;
	case ETIMEDOUT:
		return TIMED_OUT_NETS_RESULT;
	case EINTR:
		return INTERRUPTED_NETS_RESULT;
	}
	#elif _WIN32
	switch (error)
	{
	default:
		return UNKNOWN_ERROR_NETS_RESULT;
	case WSAEALREADY:
	case WSAEINPROGRESS:
	case WSAEWOULDBLOCK:
		return IN_PROGRESS_NETS_RESULT;
	case WSAEAFNOSUPPORT:
	case WSAEPROTONOSUPPORT:
	case WSAESOCKTNOSUPPORT:
	case WSAEOPNOTSUPP:
		return NOT_SUPPORTED_NETS_RESULT;
	case WSAEMFILE:
		return OUT_OF_DESCRIPTORS_NETS_RESULT;
	case WSAENOBUFS:
	case WSA_NOT_ENOUGH_MEMORY:
		return OUT_OF_MEMORY_NETS_RESULT;
	case WSAEACCES:
		return NO_ACCESS_NETS_RESULT;
	case WSAEADDRINUSE:
		return ADDRESS_IS_ALREADY_IN_USE_NETS_RESULT;
	case WSAEADDRNOTAVAIL:
		return BAD_ADDRESS_NETS_RESULT;
	case WSAEINVAL:
	case WSAEFAULT:
	case WSAENOTSOCK:
		return BAD_DATA_NETS_RESULT;
	case WSAEISCONN:
		return ALREADY_CONNECTED_NETS_RESULT;
	case WSAECONNREFUSED:
		return CONNECTION_IS_REFUSED_NETS_RESULT;
	case WSAECONNABORTED:
		return CONNECTION_IS_ABORTED_NETS_RESULT;
	case WSAECONNRESET:
		return CONNECTION_IS_RESET_NETS_RESULT;
	case WSAENETUNREACH:
		return NETWORK_IS_NOT_REACHABLE_NETS_RESULT;
	case WSAEHOSTUNREACH:
		return HOST_IS_NOT_REACHABLE_NETS_RESULT;
	case WSAETIMEDOUT:
		return TIMED_OUT_NETS_RESULT;
	case WSAEINTR:
		return INTERRUPTED_NETS_RESULT;
	}
	#endif
}
inline static NetsResult lastErrorToNetsResult()
{
	#if __linux__ || __APPLE__
	return errorToNetsResult(errno);
	#elif _WIN32
	return errorToNetsResult(WSAGetLastError());
	#endif
}
inline static NetsResult sslErrorToNetsResult(int error)
{
	#if NETS_SUPPORT_OPENSSL
	switch (error)
	{
	default:
		return UNKNOWN_ERROR_NETS_RESULT;
	case SSL_ERROR_ZERO_RETURN:
		return CONNECTION_IS_CLOSED_NETS_RESULT;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
		return IN_PROGRESS_NETS_RESULT;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		return lastErrorToNetsResult();
	}
	#else
	return NO_OPENSSL_SUPPORT_NETS_RESULT;
	#endif
}

//**********************************************************************************************************************
inline static NetsResult createSocketHandle(SocketType socketType, SocketFamily socketFamily,
	SocketAddress socketAddress, bool isBlocking, bool isOnlyIPv6, SOCKET* handle)
{
	assert(socketType < SOCKET_TYPE_COUNT);
	assert(socketFamily < SOCKET_FAMILY_COUNT);
	assert(socketAddress);

	int type, protocol;
	if (socketType == STREAM_SOCKET_TYPE)
	{
		type = SOCK_STREAM; protocol = IPPROTO_TCP;
	}
	else if (socketType == DATAGRAM_SOCKET_TYPE)
	{
		type = SOCK_DGRAM; protocol = IPPROTO_UDP;
	}
	else abort();

	int family; SOCKET_LENGTH length;
	if (socketFamily == IP_V4_SOCKET_FAMILY)
	{
		family = AF_INET; length = sizeof(struct sockaddr_in);
	}
	else if (socketFamily == IP_V6_SOCKET_FAMILY)
	{
		family = AF_INET6; length = sizeof(struct sockaddr_in6);
	}
	else abort();

	SOCKET handleInstance = socket(family, type, protocol);
	if (handleInstance == INVALID_SOCKET)
		return lastErrorToNetsResult();

	if (socketFamily == IP_V6_SOCKET_FAMILY)
	{
		#if __linux__ || __APPLE__
		int onlyV6 = isOnlyIPv6 ? 1 : 0;
		SOCKET_LENGTH v6Length = sizeof(int);
		#elif _WIN32
		BOOL onlyV6 = isOnlyIPv6 ? TRUE : FALSE;
		SOCKET_LENGTH v6Length = sizeof(BOOL);
		#endif

		if (setsockopt(handleInstance, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&onlyV6, v6Length) != 0)
		{
			closesocket(handleInstance);
			return lastErrorToNetsResult();
		}
	}

	if (!isBlocking)
	{
		#if __linux__ || __APPLE__
		int flags = fcntl(handleInstance, F_GETFL, 0);
		if (flags == -1)
		{
			closesocket(handleInstance);
			return FAILED_TO_SET_FLAG_NETS_RESULT;
		}

		int result = fcntl(handleInstance, F_SETFL, flags | O_NONBLOCK);
		#elif _WIN32
		u_long flags = 1;
		int result = ioctlsocket(handleInstance, FIONBIO, &flags);
		#endif

		if (result != 0)
		{
			closesocket(handleInstance);
			return FAILED_TO_SET_FLAG_NETS_RESULT;
		}
	}

	if (bind(handleInstance, (const struct sockaddr*)&socketAddress->handle, length) != 0)
	{
		closesocket(handleInstance);
		return lastErrorToNetsResult();
	}

	*handle = handleInstance;
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
NetsResult createSocket(SocketType type, SocketFamily family, SocketAddress localAddress, 
	bool isBlocking, bool isOnlyIPv6, SslContext sslContext, Socket* _socket)
{
	assert(type < SOCKET_TYPE_COUNT);
	assert(family < SOCKET_FAMILY_COUNT);
	assert(localAddress);
	assert(_socket);
	assert(family == IP_V6_SOCKET_FAMILY || (family == IP_V4_SOCKET_FAMILY && !isOnlyIPv6));

	#if NETS_SUPPORT_OPENSSL
	assert((type != DATAGRAM_SOCKET_TYPE) ||
		(type == DATAGRAM_SOCKET_TYPE && !sslContext));
	#else
	assert(!sslContext);
	#endif

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_NETS_RESULT;

	Socket socketInstance = calloc(1, sizeof(Socket_T));
	if (!socketInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	socketInstance->queueSize = 0;
	socketInstance->type = type;
	socketInstance->family = family;
	socketInstance->isBlocking = isBlocking;
	socketInstance->isOnlyIPv6 = isOnlyIPv6;

	SOCKET handle;
	NetsResult netsResult = createSocketHandle(type, family, localAddress, isBlocking, isOnlyIPv6, &handle);
	if (netsResult != SUCCESS_NETS_RESULT)
	{
		destroySocket(socketInstance);
		return netsResult;
	}

	socketInstance->handle = handle;

	#if NETS_SUPPORT_OPENSSL
	if (sslContext)
	{
		SSL* ssl = SSL_new(sslContext->handle);
		if (!ssl)
		{
			destroySocket(socketInstance);
			return FAILED_TO_CREATE_SSL_NETS_RESULT;
		}

		socketInstance->sslContext = sslContext;
		socketInstance->ssl = ssl;

		if (SSL_set_fd(ssl, (int)handle) != 1)
		{
			destroySocket(socketInstance);
			return FAILED_TO_CREATE_SSL_NETS_RESULT;
		}
	}
	else
	{
		socketInstance->sslContext = NULL;
	}
	#endif

	*_socket = socketInstance;
	return SUCCESS_NETS_RESULT;
}
void destroySocket(Socket socket)
{
	if (!socket)
		return;

	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	if (socket->sslContext)
		SSL_free(socket->ssl);
	#endif

	if (socket->handle)
		closesocket(socket->handle);
	free(socket);
}

//**********************************************************************************************************************
SocketType getSocketType(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->type;
}
SocketFamily getSocketFamily(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->family;
}
bool isSocketBlocking(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->isBlocking;
}
bool isSocketOnlyIPv6(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->isOnlyIPv6;
}

bool getSocketLocalAddress(Socket socket, SocketAddress socketAddress)
{
	assert(socket);
	assert(socketAddress);
	assert(networkInitialized);

	struct sockaddr_storage storage;
	memset(&storage, 0, sizeof(struct sockaddr_storage));
	SOCKET_LENGTH length = sizeof(struct sockaddr_storage);

	if (getsockname(socket->handle, (struct sockaddr*)&storage, &length) == 0)
	{
		socketAddress->handle = storage;
		return true;
	}
	return false;
}
bool getSocketRemoteAddress(Socket socket, SocketAddress socketAddress)
{
	assert(socket);
	assert(socketAddress);
	assert(networkInitialized);

	struct sockaddr_storage storage;
	memset(&storage, 0, sizeof(struct sockaddr_storage));
	SOCKET_LENGTH length = sizeof(struct sockaddr_storage);

	if (getpeername(socket->handle, (struct sockaddr*)&storage, &length) == 0)
	{
		socketAddress->handle = storage;
		return true;
	}
	return false;
}

void* getSocketHandle(Socket socket)
{
	assert(socket);
	return (void*)(size_t)socket->handle;
}
SslContext getSocketSslContext(Socket socket)
{
	#if NETS_SUPPORT_OPENSSL
	assert(socket);
	assert(networkInitialized);
	return socket->sslContext;
	#else
	return NULL;
	#endif
}

//**********************************************************************************************************************
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
	if (getsockopt(socket->handle, IPPROTO_TCP, TCP_NODELAY, (char*)&value, &length) != 0)
		abort(); // Note: invalid socket data or memory.

	#if __linux__ || __APPLE__
	return value != 0;
	#elif _WIN32
	return value != FALSE;
	#endif
}
void setSocketNoDelay(Socket socket, bool value)
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

	if (setsockopt(socket->handle, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, length) != 0)
		abort(); // Note: invalid socket data or memory.
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

//**********************************************************************************************************************
NetsResult listenSocket(Socket socket, size_t queueSize)
{
	assert(socket);
	assert(queueSize > 0);
	assert(queueSize <= getMaxSocketQueueSize());
	assert(socket->queueSize == 0);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);

	if (listen(socket->handle, (int)queueSize) != 0)
		return lastErrorToNetsResult();

	socket->queueSize = queueSize;
	return SUCCESS_NETS_RESULT;
}
NetsResult acceptSocket(Socket socket, Socket* accepted)
{
	assert(socket);
	assert(accepted);
	assert(socket->queueSize > 0);
	assert(socket->type == STREAM_SOCKET_TYPE);
	assert(networkInitialized);

	SOCKET handle = accept(socket->handle, NULL, 0);
	if (handle == INVALID_SOCKET)
		return lastErrorToNetsResult();

	Socket acceptedInstance = calloc(1, sizeof(Socket_T));
	if (!acceptedInstance)
	{
		closesocket(socket->handle);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	acceptedInstance->handle = handle;

	if (!socket->isBlocking)
	{
		#if __linux__ || __APPLE__
		int flags = fcntl(handle, F_GETFL, 0);
		if (flags == -1)
		{
			destroySocket(acceptedInstance);
			return FAILED_TO_SET_FLAG_NETS_RESULT;
		}

		int result = fcntl(handle, F_SETFL, flags | O_NONBLOCK);
		#elif _WIN32
		u_long flags = 1;
		int result = ioctlsocket(handle, FIONBIO, &flags);
		#endif

		if (result != 0)
		{
			destroySocket(acceptedInstance);
			return FAILED_TO_SET_FLAG_NETS_RESULT;
		}
	}

	#if NETS_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		SSL* ssl = SSL_new(socket->sslContext->handle);
		if (!ssl)
		{
			destroySocket(acceptedInstance);
			return FAILED_TO_CREATE_SSL_NETS_RESULT;
		}

		acceptedInstance->sslContext = socket->sslContext;
		acceptedInstance->ssl = ssl;

		if (SSL_set_fd(ssl, (int)handle) != 1)
		{
			destroySocket(acceptedInstance);
			return FAILED_TO_CREATE_SSL_NETS_RESULT;
		}
	}
	else
	{
		acceptedInstance->sslContext = NULL;
	}
	#endif

	acceptedInstance->queueSize = 0;
	acceptedInstance->type = socket->type;
	acceptedInstance->isBlocking = socket->isBlocking;
	acceptedInstance->isOnlyIPv6 = socket->isOnlyIPv6;
	*accepted = acceptedInstance;
	return SUCCESS_NETS_RESULT;
}
NetsResult acceptSslSocket(Socket socket)
{
	assert(socket);
	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	assert(socket->sslContext);

	int result = SSL_accept(socket->ssl) == 1;
	if (result != 1)
		return sslErrorToNetsResult(SSL_get_error(socket->ssl, result));
	return SUCCESS_NETS_RESULT;
	#else
	return NO_OPENSSL_SUPPORT_NETS_RESULT;
	#endif
}

//**********************************************************************************************************************
NetsResult connectSocket(Socket socket, SocketAddress remoteAddress)
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
	else abort();

	if (connect(socket->handle, (const struct sockaddr*)&remoteAddress->handle, length) != 0)
		return lastErrorToNetsResult();
	return SUCCESS_NETS_RESULT;
}
NetsResult connectSslSocket(Socket socket, const char* hostname)
{
	assert(socket);
	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	assert(socket->sslContext);

	if (hostname)
	{
		assert(strlen(hostname) > 0);
		assert(strlen(hostname) <= UINT8_MAX);

		int result = SSL_set_tlsext_host_name(socket->ssl, hostname);
		if (result != 1)
			return sslErrorToNetsResult(SSL_get_error(socket->ssl, result));
	}

	int result = SSL_connect(socket->ssl);
	if (result != 1)
		return sslErrorToNetsResult(SSL_get_error(socket->ssl, result));
	return SUCCESS_NETS_RESULT;
	#else
	return NO_OPENSSL_SUPPORT_NETS_RESULT;
	#endif
}

NetsResult shutdownSocket(Socket socket, SocketShutdown _shutdown)
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
	else abort();
	#elif _WIN32
	if (_shutdown == RECEIVE_ONLY_SOCKET_SHUTDOWN)
		type = SD_RECEIVE;
	else if (_shutdown == SEND_ONLY_SOCKET_SHUTDOWN)
		type = SD_SEND;
	else if (_shutdown == RECEIVE_SEND_SOCKET_SHUTDOWN)
		type = SD_BOTH;
	else abort();
	#endif

	// Note: Do not shutdown SSL, due to the bad documentation.

	if (shutdown(socket->handle, type) != 0)
		return lastErrorToNetsResult();
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
NetsResult socketReceive(Socket socket, void* receiveBuffer, size_t bufferSize, size_t* byteCount)
{
	assert(socket);
	assert(receiveBuffer);
	assert(bufferSize > 0);
	assert(byteCount);
	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		int result = SSL_read(socket->ssl, receiveBuffer, (int)bufferSize);
		if (result < 0)
			return sslErrorToNetsResult(SSL_get_error(socket->ssl, result));

		*byteCount = (size_t)result;
		return SUCCESS_NETS_RESULT;
	}
	#endif

	int64_t result = recv(socket->handle, (char*)receiveBuffer, (int)bufferSize, 0);
	if (result < 0)
		return lastErrorToNetsResult();

	*byteCount = (size_t)result;
	return SUCCESS_NETS_RESULT;
}
NetsResult socketSend(Socket socket, const void* sendBuffer, size_t byteCount)
{
	assert(socket);
	assert(sendBuffer);
	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		int result = SSL_write(socket->ssl, sendBuffer, (int)byteCount);
		if (result < 0)
			return sslErrorToNetsResult(SSL_get_error(socket->ssl, result));
		if (result != byteCount)
			return OUT_OF_MEMORY_NETS_RESULT;
		return SUCCESS_NETS_RESULT;
	}
	#endif

	#if __linux__ || __APPLE__
	const int flags = MSG_NOSIGNAL;
	#else
	const int flags = 0;
	#endif

	int64_t result = send(socket->handle, (const char*)sendBuffer, (int)byteCount, flags);
	if (result < 0)
		return lastErrorToNetsResult();
	if (result != byteCount)
		return OUT_OF_MEMORY_NETS_RESULT;
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
NetsResult socketReceiveFrom(Socket socket, SocketAddress remoteAddress, 
	void* receiveBuffer, size_t bufferSize, size_t* byteCount)
{
	assert(socket);
	assert(remoteAddress);
	assert(receiveBuffer);
	assert(bufferSize > 0);
	assert(byteCount);
	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	assert(!socket->sslContext);
	#endif

	struct sockaddr_storage storage;
	memset(&storage, 0, sizeof(struct sockaddr_storage));
	SOCKET_LENGTH length = sizeof(struct sockaddr_storage);

	int64_t count = recvfrom(socket->handle, (char*)receiveBuffer, 
		(int)bufferSize, 0, (struct sockaddr*)&storage, &length);
	if (count < 0)
		return lastErrorToNetsResult();

	remoteAddress->handle = storage;
	*byteCount = (size_t)count;
	return SUCCESS_NETS_RESULT;
}
NetsResult socketSendTo(Socket socket, const void* sendBuffer, size_t byteCount, SocketAddress remoteAddress)
{
	assert(socket);
	assert(sendBuffer);
	assert(remoteAddress);
	assert(networkInitialized);

	#if NETS_SUPPORT_OPENSSL
	assert(!socket->sslContext);
	#endif

	int family = remoteAddress->handle.ss_family;

	SOCKET_LENGTH length;
	if (family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else abort();

	#if __linux__ || __APPLE__
	const int flags = MSG_NOSIGNAL;
	#else
	const int flags = 0;
	#endif

	int64_t result = sendto(socket->handle, (const char*)sendBuffer, (int)byteCount, 
		flags, (const struct sockaddr*)&remoteAddress->handle, length);
	if (result < 0)
		return lastErrorToNetsResult();
	if (result != byteCount)
		return OUT_OF_MEMORY_NETS_RESULT;
	return SUCCESS_NETS_RESULT;
}

//**********************************************************************************************************************
NetsResult createSocketAddress(const char* host, const char* service, SocketAddress* socketAddress)
{
	assert(host);
	assert(strlen(host) > 0);
	assert(service);
	assert(strlen(service) > 0);
	assert(socketAddress);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_NETS_RESULT;

	SocketAddress socketAddressInstance = calloc(1, sizeof(SocketAddress_T));
	if (!socketAddressInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	struct addrinfo* addressInfos;
	if (getaddrinfo(host, service, &hints, &addressInfos) != 0)
	{
		free(socketAddressInstance);
		return FAILED_TO_RESOLVE_ADDRESS_NETS_RESULT;
	}

	memcpy(&socketAddressInstance->handle, addressInfos->ai_addr, addressInfos->ai_addrlen);
	freeaddrinfo(addressInfos);

	*socketAddress = socketAddressInstance;
	return SUCCESS_NETS_RESULT;
}
NetsResult createAnySocketAddress(SocketFamily family, SocketAddress* socketAddress)
{
	assert(family < SOCKET_FAMILY_COUNT);
	assert(socketAddress);

	if (family == IP_V4_SOCKET_FAMILY)
		return createSocketAddress(ANY_IP_ADDRESS_V4, ANY_IP_ADDRESS_SERVICE, socketAddress);
	if (family == IP_V6_SOCKET_FAMILY)
		return createSocketAddress(ANY_IP_ADDRESS_V6, ANY_IP_ADDRESS_SERVICE, socketAddress);
	else abort();
}
SocketAddress createSocketAddressCopy(SocketAddress socketAddress)
{
	assert(socketAddress);

	SocketAddress socketAddressInstance = malloc(sizeof(SocketAddress_T));
	if (!socketAddressInstance)
		return NULL;

	memcpy(socketAddressInstance, socketAddress, sizeof(SocketAddress_T));
	return socketAddressInstance;
}
void destroySocketAddress(SocketAddress socketAddress)
{
	if (!socketAddress)
		return;
	assert(networkInitialized);
	free(socketAddress);
}

//**********************************************************************************************************************
NetsResult resolveSocketAddresses(const char* host, const char* service, SocketFamily family,
	SocketType type, SocketAddress** socketAddresses, size_t* addressCount)
{
	assert(host);
	assert(strlen(host) > 0);
	assert(service);
	assert(strlen(service) > 0);
	assert(family < SOCKET_FAMILY_COUNT);
	assert(type < SOCKET_TYPE_COUNT);
	assert(socketAddresses);
	assert(addressCount);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_NETS_RESULT;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_ADDRCONFIG;

	if (family == IP_V4_SOCKET_FAMILY)
		hints.ai_family = AF_INET;
	else if (family == IP_V6_SOCKET_FAMILY)
		hints.ai_family = AF_INET6;
	else abort();

	if (type == STREAM_SOCKET_TYPE)
	{
		hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
	}
	else if (type == DATAGRAM_SOCKET_TYPE)
	{
		hints.ai_socktype = SOCK_DGRAM; hints.ai_protocol = IPPROTO_UDP;
	}
	else abort();

	struct addrinfo* addressInfos;
	if (getaddrinfo(host, service, &hints, &addressInfos) != 0)
		return FAILED_TO_RESOLVE_ADDRESS_NETS_RESULT;

	SocketAddress* addresses = malloc(sizeof(SocketAddress));
	if (!addresses)
	{
		freeaddrinfo(addressInfos);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	SocketAddress socketAddress = malloc(sizeof(SocketAddress_T));
	if (!socketAddress)
	{
		destroySocketAddresses(addresses, 0);
		freeaddrinfo(addressInfos);
		return OUT_OF_MEMORY_NETS_RESULT;
	}

	addresses[0] = socketAddress;
	memcpy(&socketAddress->handle, addressInfos->ai_addr, addressInfos->ai_addrlen);

	size_t count = 1;
	struct addrinfo* nextAddressInfos = addressInfos->ai_next;

	while (nextAddressInfos)
	{
		SocketAddress* newAddresses = realloc(addresses, (count + 1) * sizeof(SocketAddress));
		if (!newAddresses)
		{
			destroySocketAddresses(addresses, count);
			freeaddrinfo(addressInfos);
			return OUT_OF_MEMORY_NETS_RESULT;
		}

		addresses = newAddresses;

		socketAddress = malloc(sizeof(SocketAddress_T));
		if (!socketAddress)
		{
			destroySocketAddresses(addresses, count);
			freeaddrinfo(addressInfos);
			return OUT_OF_MEMORY_NETS_RESULT;
		}

		addresses[count++] = socketAddress;
		memcpy(&socketAddress->handle, nextAddressInfos->ai_addr, nextAddressInfos->ai_addrlen);
		nextAddressInfos = nextAddressInfos->ai_next;
	}

	freeaddrinfo(addressInfos);

	*socketAddresses = addresses;
	*addressCount = count;
	return SUCCESS_NETS_RESULT;
}
void destroySocketAddresses(SocketAddress* socketAddresses, size_t addressCount)
{
	if (!socketAddresses)
		return;
	for (size_t i = 0; i < addressCount; i++)
		destroySocketAddress(socketAddresses[i]);
	free(socketAddresses);
}

//**********************************************************************************************************************
void getUrlParts(const char* url, size_t urlLength, size_t* _hostOffset, size_t* _hostLength, 
	size_t* _serviceOffset, size_t* _serviceLength, size_t* _pathOffset)
{
	assert(url);
	assert(urlLength > 0);
	assert((_hostOffset && _hostLength) || (!_hostOffset && !_hostLength));
	assert((_serviceOffset && _serviceLength) || (!_serviceOffset && !_serviceLength));

	size_t serviceLength = 0, hostOffset = 0, i = 0;
	while (i < urlLength)
	{
		const char* pointer = memchr(url + i, ':', urlLength - i);
		if (!pointer)
			break;

		i = pointer - url;

		if (i + 2 < urlLength && url[i + 1] == '/' && url[i + 2] == '/')
		{
			pointer = memchr(url + i + 3, '@', urlLength - (i + 3));
			if (pointer)
			{
				size_t j = pointer - url;
				serviceLength = i;
				hostOffset = j + 1;
			}
			else
			{
				serviceLength = i;
				hostOffset = i + 3;
			}
			break;
		}

		i++;
	}

	size_t portLength = 0, portOffset = 0, hostLength = 0, pathOffset = 0;
	i = 0;

	while (i < urlLength)
	{
		const char* pointer = memchr(url + i, ':', urlLength - i);
		if (!pointer)
			break;

		i = pointer - url;

		if (i + 1 < urlLength && url[i + 1] != '/')
		{
			hostLength = i - hostOffset; portOffset = i + 1;
			pointer = memchr(url + portOffset, '/', urlLength - portOffset);
			if (pointer)
			{
				size_t j = pointer - url;
				portLength = j - portOffset;
				pathOffset = j + 1;
			}
			else
			{
				portLength = urlLength - i;
				pathOffset = urlLength;
			}
			break;
		}

		i++;
	}

	if (pathOffset == 0)
	{
		const char* pointer = memchr(url + hostOffset, '/', urlLength - hostOffset);
		if (pointer)
		{
			size_t index = pointer - url;
			hostLength = index - hostOffset;
			pathOffset = index + 1;
		}
		else
		{
			hostLength = urlLength - hostOffset;
			pathOffset = urlLength;
		}
	}

	if (_hostOffset)
	{
		*_hostOffset = hostOffset; *_hostLength = hostLength;
	}

	if (portLength != 0)
	{
		*_serviceOffset = portOffset; *_serviceLength = portLength;
	}
	else
	{
		*_serviceOffset = 0; *_serviceLength = serviceLength;
	}

	if (_pathOffset)
		*_pathOffset = pathOffset;
}

//**********************************************************************************************************************
void copySocketAddress(SocketAddress sourceAddress, SocketAddress destinationAddress)
{
	assert(sourceAddress);
	assert(destinationAddress);
	memcpy(&destinationAddress->handle, &sourceAddress->handle, sizeof(struct sockaddr_storage));
}

int compareSocketAddress(SocketAddress a, SocketAddress b)
{
	// Note: a and b should not be NULL!
	// Skipping here assertions for debug build speed.

	int family = a->handle.ss_family;
	if (family == AF_INET)
		return memcmp(&a->handle, &b->handle, sizeof(struct sockaddr_in));
	if (family == AF_INET6)
		return memcmp(&a->handle, &b->handle, sizeof(struct sockaddr_in6));
	abort();
}

SocketFamily getSocketAddressFamily(SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;
	if (family == AF_INET)
		return IP_V4_SOCKET_FAMILY;
	if (family == AF_INET6)
		return IP_V6_SOCKET_FAMILY;
	abort();
}
size_t getSocketFamilyIpSize(SocketFamily family)
{
	assert(family < SOCKET_FAMILY_COUNT);
	assert(networkInitialized);

	if (family == IP_V4_SOCKET_FAMILY)
		return sizeof(struct in_addr);
	if (family == IP_V6_SOCKET_FAMILY)
		return sizeof(struct in6_addr);
	abort();
}
size_t getSocketAddressIpSize(SocketAddress socketAddress)
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

//**********************************************************************************************************************
const uint8_t* getSocketAddressIP(SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;
	if (family == AF_INET)
		return (const uint8_t*)&((struct sockaddr_in*)&socketAddress->handle)->sin_addr;
	if (family == AF_INET6)
		return (const uint8_t*)&((struct sockaddr_in6*)&socketAddress->handle)->sin6_addr;
	abort();
}
void setSocketAddressIP(SocketAddress socketAddress, const uint8_t* ip)
{
	assert(socketAddress);
	assert(ip);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;
	if (family == AF_INET)
		memcpy(&((struct sockaddr_in*)&socketAddress->handle)->sin_addr, ip, sizeof(struct in_addr));
	else if (family == AF_INET6)
		memcpy(&((struct sockaddr_in6*)&socketAddress->handle)->sin6_addr, ip, sizeof(struct in6_addr));
	else abort();
}

uint16_t getSocketAddressPort(SocketAddress socketAddress)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;
	if (family == AF_INET)
	{
		struct sockaddr_in* address4 = (struct sockaddr_in*)&socketAddress->handle;
		return ntohs(address4->sin_port);
	}
	if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 = (struct sockaddr_in6*)&socketAddress->handle;
		return ntohs(address6->sin6_port);
	}
	abort();
}
void setSocketAddressPort(SocketAddress socketAddress, uint16_t port)
{
	assert(socketAddress);
	assert(networkInitialized);

	int family = socketAddress->handle.ss_family;
	if (family == AF_INET)
	{
		struct sockaddr_in* address4 = (struct sockaddr_in*)&socketAddress->handle;
		address4->sin_port = htons(port);
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 = (struct sockaddr_in6*)&socketAddress->handle;
		address6->sin6_port = htons(port);
	}
	else abort();
}

//**********************************************************************************************************************
bool getSocketAddressHost(SocketAddress socketAddress, char* host, size_t length)
{
	assert(socketAddress);
	assert(host);
	assert(length > 0);
	assert(networkInitialized);

	int flags = NI_NUMERICHOST;
	return getnameinfo((const struct sockaddr*)&socketAddress->handle, 
		sizeof(struct sockaddr_storage), host, (SOCKET_LENGTH)length, NULL, 0, flags) == 0;
}
bool getSocketAddressService(SocketAddress socketAddress, char* service, size_t length)
{
	assert(socketAddress);
	assert(service);
	assert(length > 0);
	assert(networkInitialized);

	int flags = NI_NUMERICSERV;
	return getnameinfo((const struct sockaddr*)&socketAddress->handle,
		sizeof(struct sockaddr_storage), NULL, 0, service, (SOCKET_LENGTH)length, flags) == 0;
}
bool getSocketAddressHostService(SocketAddress socketAddress, char* host, size_t hostLength, char* service, size_t serviceLength)
{
	assert(socketAddress);
	assert(host);
	assert(hostLength > 0);
	assert(service);
	assert(serviceLength > 0);
	assert(networkInitialized);

	int flags = NI_NUMERICHOST | NI_NUMERICSERV;
	return getnameinfo((const struct sockaddr*)&socketAddress->handle, sizeof(struct sockaddr_storage), 
		host, (SOCKET_LENGTH)hostLength, service, (SOCKET_LENGTH)serviceLength, flags) == 0;
}

//**********************************************************************************************************************
NetsResult createPublicSslContext(SslProtocol sslProtocol, const char* certificateFilePath,
	const char* certificatesDirectory, SslContext* sslContext)
{
	#if NETS_SUPPORT_OPENSSL
	assert(sslProtocol < SSL_PROTOCOL_COUNT);
	assert(sslContext);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_NETS_RESULT;

	SslContext sslContextInstance = calloc(1, sizeof(SslContext_T));
	if (!sslContextInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	SSL_CTX* handle;
	switch (sslProtocol)
	{
	case TLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case TLS_1_2_SECURITY_PROTOCOL:
		#if NETS_SUPPORT_DEPRECATED_SSL
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
		#else
		abort(); // Note: TLS 1.2 support is deprecated!
		#endif
	default: abort();
	}

	if (!handle)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_CREATE_SSL_NETS_RESULT;
	}

	sslContextInstance->handle = handle;

	int result;
	if (certificateFilePath || certificatesDirectory)
	{
		if (certificateFilePath)
			assert(strlen(certificateFilePath) > 0);
		result = SSL_CTX_load_verify_locations(handle, certificateFilePath, certificatesDirectory);
	}
	else
	{
		result = SSL_CTX_set_default_verify_paths(handle);
	}

	if (result != 1)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_NETS_RESULT;
	}

	*sslContext = sslContextInstance;
	return SUCCESS_NETS_RESULT;
	#else
	return NO_OPENSSL_SUPPORT_NETS_RESULT;
	#endif
}

//**********************************************************************************************************************
NetsResult createPrivateSslContext(SslProtocol sslProtocol, const char* certificateFilePath,
	const char* privateKeyFilePath, bool certificateChain, SslContext* sslContext)
{
	#if NETS_SUPPORT_OPENSSL
	assert(sslProtocol < SSL_PROTOCOL_COUNT);
	assert(certificateFilePath);
	assert(strlen(certificateFilePath) > 0);
	assert(privateKeyFilePath);
	assert(strlen(privateKeyFilePath) > 0);
	assert(sslContext);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_NETS_RESULT;

	SslContext sslContextInstance = calloc(1, sizeof(SslContext_T));
	if (!sslContextInstance)
		return OUT_OF_MEMORY_NETS_RESULT;

	SSL_CTX* handle;
	switch (sslProtocol)
	{
	case TLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case TLS_1_2_SECURITY_PROTOCOL:
		#if NETS_SUPPORT_DEPRECATED_SSL
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
		#else
		abort(); // Note: TLS 1.2 support is deprecated!
		#endif
	default: abort();
	}

	if (!handle)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_CREATE_SSL_NETS_RESULT;
	}

	sslContextInstance->handle = handle;

	int result;
	if (certificateChain)
		result = SSL_CTX_use_certificate_chain_file(handle, certificateFilePath);
	else
		result = SSL_CTX_use_certificate_file(handle, certificateFilePath, SSL_FILETYPE_PEM);

	if (result != 1)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_NETS_RESULT;
	}

	if (SSL_CTX_use_PrivateKey_file(handle, privateKeyFilePath, SSL_FILETYPE_PEM) != 1)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_NETS_RESULT;
	}
	if (SSL_CTX_check_private_key(handle) != 1)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_NETS_RESULT;
	}

	*sslContext = sslContextInstance;
	return SUCCESS_NETS_RESULT;
	#else
	return NO_OPENSSL_SUPPORT_NETS_RESULT;
	#endif
}

//**********************************************************************************************************************
void destroySslContext(SslContext sslContext)
{
	#if NETS_SUPPORT_OPENSSL
	if (!sslContext)
		return;

	assert(networkInitialized);
	SSL_CTX_free(sslContext->handle);
	free(sslContext);
	#else
	abort(); // Note: OpenSSL support is disabled.
	#endif
}

SslProtocol getSslContextProtocol(SslContext sslContext)
{
	#if NETS_SUPPORT_OPENSSL
	assert(sslContext);
	assert(networkInitialized);

	const SSL_METHOD* method = SSL_CTX_get_ssl_method(sslContext->handle);
	if (method == TLS_method())
		return TLS_SECURITY_PROTOCOL;
	if (method == TLSv1_2_method())
		return TLS_1_2_SECURITY_PROTOCOL;
	abort();
	#else
	abort(); // Note: OpenSSL support is disabled.
	#endif
}

NetsResult sHandleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, 
	uint8_t* messageBuffer, size_t messageBufferSize, size_t* messageByteCount, uint8_t messageLengthSize, 
	NetsResult(*receiveFunction)(StreamMessage, void*), void* functionHandle)
{
	return handleStreamMessage(receiveBuffer, byteCount, messageBuffer, messageBufferSize, 
		messageByteCount, messageLengthSize, receiveFunction, functionHandle);
}