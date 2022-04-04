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
	AddressFamily family;
	bool isBlocking;
#if MPNW_SUPPORT_OPENSSL
	uint8_t _alignment[1];
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

void disableSigpipe()
{
#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_IGN);
#elif _WIN32
	abort();
#endif
}

inline static MpnwResult errorToMpnwResult(int error)
{
#if __linux__ || __APPLE__
	switch (error)
	{
	default:
		return UNKNOWN_ERROR_MPNW_RESULT;
	case EALREADY:
	case EINPROGRESS:
	case EWOULDBLOCK:
		return IN_PROGRESS_MPNW_RESULT;
	case EAFNOSUPPORT:
	case EPROTONOSUPPORT:
	case ESOCKTNOSUPPORT:
	case EOPNOTSUPP:
		return NOT_SUPPORTED_MPNW_RESULT;
	case EMFILE:
		return OUT_OF_DESCRIPTORS_MPNW_RESULT;
	case ENOBUFS:
	case ENOMEM:
		return OUT_OF_MEMORY_MPNW_RESULT;
	case EACCES:
	case EPERM:
		return NO_ACCESS_MPNW_RESULT;
	case EADDRINUSE:
		return ADDRESS_IS_ALREADY_IN_USE_MPNW_RESULT;
	case EADDRNOTAVAIL:
		return BAD_ADDRESS_MPNW_RESULT;
	case EINVAL:
	case EFAULT:
	case ENOTSOCK:
	case EBADF:
		return BAD_DATA_MPNW_RESULT;
	case EISCONN:
		return ALREADY_CONNECTED_MPNW_RESULT;
	case ECONNREFUSED:
		return CONNECTION_IS_REFUSED_MPNW_RESULT;
	case ECONNABORTED:
		return CONNECTION_IS_ABORTED_MPNW_RESULT;
	case ECONNRESET:
		return CONNECTION_IS_RESET_MPNW_RESULT;
	case EPIPE:
		return CONNECTION_IS_CLOSED_MPNW_RESULT;
	case ENETUNREACH:
		return NETWORK_IS_NOT_REACHABLE_MPNW_RESULT;
	case EHOSTUNREACH:
		return HOST_IS_NOT_REACHABLE_MPNW_RESULT;
	case ETIMEDOUT:
		return TIMED_OUT_MPNW_RESULT;
	case EINTR:
		return INTERRUPTED_MPNW_RESULT;
	}
#elif _WIN32
	switch (error)
	{
	default:
		return UNKNOWN_ERROR_MPNW_RESULT;
	case WSAEALREADY:
	case WSAEINPROGRESS:
	case WSAEWOULDBLOCK:
		return IN_PROGRESS_MPNW_RESULT;
	case WSAEAFNOSUPPORT:
	case WSAEPROTONOSUPPORT:
	case WSAESOCKTNOSUPPORT:
	case WSAEOPNOTSUPP:
		return NOT_SUPPORTED_MPNW_RESULT;
	case WSAEMFILE:
		return OUT_OF_DESCRIPTORS_MPNW_RESULT;
	case WSAENOBUFS:
	case WSA_NOT_ENOUGH_MEMORY:
		return OUT_OF_MEMORY_MPNW_RESULT;
	case WSAEACCES:
		return NO_ACCESS_MPNW_RESULT;
	case WSAEADDRINUSE:
		return ADDRESS_IS_ALREADY_IN_USE_MPNW_RESULT;
	case WSAEADDRNOTAVAIL:
		return BAD_ADDRESS_MPNW_RESULT;
	case WSAEINVAL:
	case WSAEFAULT:
	case WSAENOTSOCK:
		return BAD_DATA_MPNW_RESULT;
	case WSAEISCONN:
		return ALREADY_CONNECTED_MPNW_RESULT;
	case WSAECONNREFUSED:
		return CONNECTION_IS_REFUSED_MPNW_RESULT;
	case WSAECONNABORTED:
		return CONNECTION_IS_ABORTED_MPNW_RESULT;
	case WSAECONNRESET:
		return CONNECTION_IS_RESET_MPNW_RESULT;
	case WSAENETUNREACH:
		return NETWORK_IS_NOT_REACHABLE_MPNW_RESULT;
	case WSAEHOSTUNREACH:
		return HOST_IS_NOT_REACHABLE_MPNW_RESULT;
	case WSAETIMEDOUT:
		return TIMED_OUT_MPNW_RESULT;
	case WSAEINTR:
		return INTERRUPTED_MPNW_RESULT;
	}
#endif
}
inline static MpnwResult lastErrorToMpnwResult()
{
#if __linux__ || __APPLE__
	return errorToMpnwResult(errno);
#elif _WIN32
	return errorToMpnwResult(WSAGetLastError());
#endif
}
inline static MpnwResult sslErrorToMpnwResult(int error)
{
#if MPNW_SUPPORT_OPENSSL
	switch (error)
	{
	default:
		return UNKNOWN_ERROR_MPNW_RESULT;
	case SSL_ERROR_ZERO_RETURN:
		return CONNECTION_IS_CLOSED_MPNW_RESULT;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
		return IN_PROGRESS_MPNW_RESULT;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		return lastErrorToMpnwResult();
	}
#else
	abort();
#endif
}

inline static MpnwResult createSocketHandle(
	SocketType socketType,
	AddressFamily addressFamily,
	SocketAddress socketAddress,
	bool isBlocking,
	SOCKET* handle)
{
	assert(socketType < SOCKET_TYPE_COUNT);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(socketAddress);

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

	SOCKET handleInstance = socket(
		family,
		type,
		protocol);

	if (handleInstance == INVALID_SOCKET)
		return lastErrorToMpnwResult();

	int result = bind(
		handleInstance,
		(const struct sockaddr*)&socketAddress->handle,
		length);

	if (result != 0)
	{
		closesocket(handleInstance);
		return lastErrorToMpnwResult();
	}

	if (!isBlocking)
	{
#if __linux__ || __APPLE__
		int flags = fcntl(
			handleInstance,
			F_GETFL,
			0);

		if (flags == -1)
		{
			closesocket(handleInstance);
			return FAILED_TO_SET_FLAG_MPNW_RESULT;
		}

		result = fcntl(
			handleInstance,
			F_SETFL,
			flags | O_NONBLOCK);
#elif _WIN32
		u_long flags = 1;

		result = ioctlsocket(
    		handleInstance,
    		FIONBIO,
    		&flags);
#endif

		if (result != 0)
		{
			closesocket(handleInstance);
			return FAILED_TO_SET_FLAG_MPNW_RESULT;
		}
	}

	*handle = handleInstance;
	return SUCCESS_MPNW_RESULT;
}
MpnwResult createSocket(
	SocketType socketType,
	AddressFamily addressFamily,
	SocketAddress socketAddress,
	bool isBlocking,
	SslContext sslContext,
	Socket* _socket)
{
	assert(socketType < SOCKET_TYPE_COUNT);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(socketAddress);
	assert(_socket);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

#if MPNW_SUPPORT_OPENSSL
	assert((socketType != DATAGRAM_SOCKET_TYPE) ||
		(socketType == DATAGRAM_SOCKET_TYPE && !sslContext));
#else
	assert(!sslContext);
#endif

	Socket socketInstance = calloc(
		1, sizeof(Socket_T));

	if (!socketInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	socketInstance->queueSize = 0;
	socketInstance->type = socketType;
	socketInstance->family = addressFamily;
	socketInstance->isBlocking = isBlocking;
#if MPNW_SUPPORT_OPENSSL
	socketInstance->sslContext = sslContext;
#endif

	SOCKET handle;

	MpnwResult mpnwResult = createSocketHandle(
		socketType,
		addressFamily,
		socketAddress,
		isBlocking,
		&handle);

	if (mpnwResult != SUCCESS_MPNW_RESULT)
	{
		destroySocket(socketInstance);
		return mpnwResult;
	}

	socketInstance->handle = handle;

#if MPNW_SUPPORT_OPENSSL
	if (sslContext)
	{
		SSL* ssl = SSL_new(sslContext->handle);

		if (!ssl)
		{
			destroySocket(socketInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		socketInstance->ssl = ssl;

		int result = SSL_set_fd(ssl, (int)handle);

		if (result != 1)
		{
			destroySocket(socketInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}
	}
#endif

	*_socket = socketInstance;
	return SUCCESS_MPNW_RESULT;
}
void destroySocket(Socket socket)
{
	if (!socket)
		return;

	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext)
		SSL_free(socket->ssl);
#endif

	if (socket->handle)
		closesocket(socket->handle);

	free(socket);
}

SocketType getSocketType(Socket socket)
{
	assert(socket);
	assert(networkInitialized);
	return socket->type;
}
AddressFamily getSocketFamily(Socket socket)
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

bool isSocketOnlyV6(
	Socket socket)
{
	assert(socket);
	assert(networkInitialized);

#if __linux__ || __APPLE__
	int value;
#elif _WIN32
	BOOL value;
#endif

	SOCKET_LENGTH length;

	int result = getsockopt(
		socket->handle,
		IPPROTO_IPV6,
		IPV6_V6ONLY,
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
void setSocketOnlyV6(
	Socket socket,
	bool value)
{
	assert(socket);
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
		IPPROTO_IPV6,
		IPV6_V6ONLY,
		(char*)&noDelay,
		length);

	if (result != 0)
		abort();
}

bool isSocketNoDelay(
	Socket socket)
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

MpnwResult listenSocket(
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
		return lastErrorToMpnwResult();

	socket->queueSize = queueSize;
	return SUCCESS_MPNW_RESULT;
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

	Socket acceptedInstance = calloc(
		1, sizeof(Socket_T));

	if (!acceptedInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	SOCKET handle = accept(socket->handle, NULL, 0);

	if (handle == INVALID_SOCKET)
	{
		destroySocket(acceptedInstance);
		return lastErrorToMpnwResult();
	}

	if (!socket->isBlocking)
	{
#if __linux__ || __APPLE__
		int flags = fcntl(
			handle,
			F_GETFL,
			0);

		if (flags == -1)
		{
			destroySocket(acceptedInstance);
			return FAILED_TO_SET_FLAG_MPNW_RESULT;
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
			destroySocket(acceptedInstance);
			return FAILED_TO_SET_FLAG_MPNW_RESULT;
		}
	}

	acceptedInstance->queueSize = 0;
	acceptedInstance->handle = handle;
	acceptedInstance->type = socket->type;
	acceptedInstance->isBlocking = socket->isBlocking;

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext)
	{
		SSL* ssl = SSL_new(socket->sslContext->handle);

		if (!ssl)
		{
			destroySocket(acceptedInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		int result = SSL_set_fd(ssl, (int)handle);

		if (result != 1)
		{
			destroySocket(acceptedInstance);
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

MpnwResult acceptSslSocket(Socket socket)
{
	assert(socket);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	assert(socket->sslContext);
	int result = SSL_accept(socket->ssl) == 1;

	if (result != 1)
	{
		return sslErrorToMpnwResult(SSL_get_error(
			socket->ssl, result));
	}

	return SUCCESS_MPNW_RESULT;
#else
	abort();
#endif
}

MpnwResult connectSocket(
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

	if (result != 0)
		return lastErrorToMpnwResult();

	return SUCCESS_MPNW_RESULT;
}
MpnwResult connectSslSocket(
	Socket socket,
	const char* hostname)
{
	assert(socket);
	assert(networkInitialized);

#if MPNW_SUPPORT_OPENSSL
	assert(socket->sslContext);

	if (hostname)
		SSL_set_tlsext_host_name(socket->ssl, hostname);

	int result = SSL_connect(socket->ssl);

	if (result == 1)
		return SUCCESS_MPNW_RESULT;

	return sslErrorToMpnwResult(SSL_get_error(
		socket->ssl, result));
#else
	abort();
#endif
}

MpnwResult shutdownSocket(
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

	int result = shutdown(
		socket->handle,
		type);

	if (result != 0)
		return lastErrorToMpnwResult();

	return SUCCESS_MPNW_RESULT;
}

MpnwResult socketReceive(
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
		{
			return sslErrorToMpnwResult(SSL_get_error(
				socket->ssl, result));
		}

		*byteCount = (size_t)result;
		return SUCCESS_MPNW_RESULT;
	}
#endif

	int64_t result = recv(
		socket->handle,
		(char*)receiveBuffer,
		(int)bufferSize,
		0);

	if (result < 0)
		return lastErrorToMpnwResult();

	*byteCount = (size_t)result;
	return SUCCESS_MPNW_RESULT;
}
MpnwResult socketSend(
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
		int result = SSL_write(
			socket->ssl,
			sendBuffer,
			(int)byteCount);

		if (result < 0)
		{
			return sslErrorToMpnwResult(SSL_get_error(
				socket->ssl, result));
		}

		if (result != byteCount)
			return OUT_OF_MEMORY_MPNW_RESULT;

		return SUCCESS_MPNW_RESULT;
	}
#endif

	int64_t result = send(
		socket->handle,
		(const char*)sendBuffer,
		(int)byteCount,
		0);

	if (result < 0)
		return lastErrorToMpnwResult();
	if (result != byteCount)
		return OUT_OF_MEMORY_MPNW_RESULT;

	return SUCCESS_MPNW_RESULT;
}
MpnwResult socketReceiveFrom(
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
		return lastErrorToMpnwResult();

	remoteAddress->handle = storage;
	*byteCount = (size_t)count;
	return SUCCESS_MPNW_RESULT;
}
MpnwResult socketSendTo(
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

	int64_t result = sendto(
		socket->handle,
		(const char*)sendBuffer,
		(int)byteCount,
		0,
		(const struct sockaddr*)&remoteAddress->handle,
		length);

	if (result < 0)
		return lastErrorToMpnwResult();
	if (result != byteCount)
		return OUT_OF_MEMORY_MPNW_RESULT;

	return SUCCESS_MPNW_RESULT;
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
		return OUT_OF_MEMORY_MPNW_RESULT;

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
MpnwResult createAnySocketAddress(
	AddressFamily addressFamily,
	SocketAddress* socketAddress)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(socketAddress);

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		return createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_SERVICE,
			socketAddress);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		return createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_SERVICE,
			socketAddress);
	}
	else
	{
		abort();
	}
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
	SocketAddress socketAddress)
{
	assert(host);
	assert(service);
	assert(family < ADDRESS_FAMILY_COUNT);
	assert(type < SOCKET_TYPE_COUNT);
	assert(socketAddress);

	if (!networkInitialized)
		return NETWORK_IS_NOT_INITIALIZED_MPNW_RESULT;

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
		return FAILED_TO_GET_ADDRESS_INFO_MPNW_RESULT;
	}

	memcpy(&socketAddress->handle,
		addressInfos->ai_addr,
		addressInfos->ai_addrlen);

	freeaddrinfo(addressInfos);
	return SUCCESS_MPNW_RESULT;
}
void destroySocketAddress(SocketAddress socketAddress)
{
	if (!socketAddress)
		return;

	assert(networkInitialized);
	free(socketAddress);
}

MpnwResult allocateUrlHostService(
	const char* url,
	size_t urlLength,
	char** host,
	size_t* hostLength,
	char** service,
	size_t* serviceLength,
	size_t* _pathOffset)
{
	assert(url);
	assert(urlLength > 0);
	assert(host);
	assert(hostLength);
	assert(service);
	assert(serviceLength);

	size_t serviceSize = 0, hostOffset = 0;

	for (size_t i = 0; i < urlLength; i++)
	{
		if (i + 2 < urlLength &&
			url[i] == ':' &&
			url[i + 1] == '/' &&
			url[i + 2] == '/')
		{
			serviceSize = i;
			hostOffset = i + 3;

			for (size_t j = i + 3; j < urlLength; j++)
			{
				if (url[j] == '@')
				{
					serviceSize = i;
					hostOffset = j + 1;
					break;
				}
			}

			break;
		}
	}

	size_t portSize = 0, portOffset = 0, hostSize = 0, pathOffset = 0;

	for (size_t i = hostOffset; i < urlLength; i++)
	{
		if (i + 1 < urlLength &&
			url[i] == ':' &&
			url[i + 1] != '/')
		{
			portSize = urlLength - i;
			portOffset = i + 1;
			hostSize =  i - hostOffset;
			pathOffset = urlLength;

			for (size_t j = i + 1; j < urlLength; j++)
			{
				if (url[j] == '/')
				{
					portOffset = i + 1;
					portSize = j - portOffset;
					pathOffset = j + 1;
					break;
				}
			}

			break;
		}
	}

	if (pathOffset == 0)
	{
		hostSize = urlLength - hostOffset;
		pathOffset = urlLength;

		for (size_t i = hostOffset; i < urlLength; i++)
		{
			if (url[i] == '/')
			{
				hostSize = i - hostOffset;
				pathOffset = i + 1;
				break;
			}
		}
	}

	if (hostSize == 0)
		return BAD_DATA_MPNW_RESULT;

	char* hostInstance = malloc((hostSize + 1));

	if (!hostInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

	memcpy(hostInstance, url + hostOffset, hostSize);
	hostInstance[hostSize] = '\0';

	char* serviceInstance;

	if (portSize != 0)
	{
		serviceInstance = malloc((portSize + 1));

		if (!serviceInstance)
		{
			free(hostInstance);
			return OUT_OF_MEMORY_MPNW_RESULT;
		}

		memcpy(serviceInstance, url + portOffset, portSize);
		serviceInstance[portSize] = '\0';
	}
	else if (serviceSize != 0)
	{
		serviceInstance = malloc((serviceSize + 1));

		if (!serviceInstance)
		{
			free(hostInstance);
			return OUT_OF_MEMORY_MPNW_RESULT;
		}

		memcpy(serviceInstance, url, serviceSize);
		serviceInstance[serviceSize] = '\0';
	}
	else
	{
		serviceInstance = NULL;
	}

	*host = hostInstance;
	*hostLength = hostSize;
	*service = serviceInstance;
	*serviceLength = serviceSize;

	if (_pathOffset)
		*_pathOffset = pathOffset;

	return SUCCESS_MPNW_RESULT;
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

	SslContext sslContextInstance = calloc(
		1, sizeof(SslContext_T));

	if (!sslContextInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

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
		destroySslContext(sslContextInstance);
		return FAILED_TO_CREATE_SSL_MPNW_RESULT;
	}

	sslContextInstance->handle = handle;

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
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

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

	SslContext sslContextInstance = calloc(
		1, sizeof(SslContext_T));

	if (!sslContextInstance)
		return OUT_OF_MEMORY_MPNW_RESULT;

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
		destroySslContext(sslContextInstance);
		return FAILED_TO_CREATE_SSL_MPNW_RESULT;
	}

	sslContextInstance->handle = handle;

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
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	result = SSL_CTX_use_PrivateKey_file(
		handle,
		privateKeyFilePath,
		SSL_FILETYPE_PEM);

	if (result != 1)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	result = SSL_CTX_check_private_key(handle);

	if (result != 1)
	{
		destroySslContext(sslContextInstance);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	*sslContext = sslContextInstance;
	return SUCCESS_MPNW_RESULT;
#else
	return NO_OPENSSL_SUPPORT_MPNW_RESULT;
#endif
}

void destroySslContext(SslContext sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	if (!sslContext)
		return;

	assert(networkInitialized);

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
