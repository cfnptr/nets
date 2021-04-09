#include "mpnw/socket.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

#if MPNW_HAS_OPENSSL
#include "openssl/ssl.h"
#include "openssl/err.h"
#else
#define SSL_CTX void
#endif

struct Socket
{
	SOCKET handle;
	bool listening;
	bool blocking;

#if MPNW_HAS_OPENSSL
	SslContext* sslContext;
	SSL* ssl;
#endif
};

struct SocketAddress
{
	struct sockaddr_storage handle;
};

struct SslContext
{
	SSL_CTX* handle;
};

static bool networkInitialized = false;

bool initializeNetwork()
{
	if (networkInitialized == true)
		return false;

#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_IGN);
#elif _WIN32
	int result = WSAStartup(
		MAKEWORD(2,2),
		&wsaData);

	if (result != 0)
		return false;
#endif

#if MPNW_HAS_OPENSSL
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
#endif

	networkInitialized = true;
	return true;
}
void terminateNetwork()
{
	if(networkInitialized == false)
		return;

#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_DFL);
#elif _WIN32
	int result = WSACleanup();

	if (result != 0)
		abort();
#endif

#if MPNW_HAS_OPENSSL
	EVP_cleanup();
#endif

	networkInitialized = false;
}
bool isNetworkInitialized()
{
	return networkInitialized;
}

Socket* createSocket(
	uint8_t _type,
	uint8_t _family,
	const SocketAddress* address,
	bool listening,
	bool blocking,
	SslContext* sslContext)
{
	assert(networkInitialized == true);
	assert(_type < SOCKET_TYPE_COUNT);
	assert(_family < ADDRESS_FAMILY_COUNT);
	assert(address != NULL);

#if !MPNW_HAS_OPENSSL
	assert(sslContext == NULL);
#endif

	Socket* _socket = malloc(sizeof(Socket));

	if (_socket == NULL)
		return NULL;

	int type, protocol, family;
	SOCKET_LENGTH length;

	if (_type == STREAM_SOCKET_TYPE)
	{
		type = SOCK_STREAM;
		protocol = IPPROTO_TCP;
	}
	else if (_type == DATAGRAM_SOCKET_TYPE)
	{
		type = SOCK_DGRAM;
		protocol = IPPROTO_UDP;
	}
	else
	{
		free(_socket);
		return NULL;
	}

	if (_family == IP_V4_ADDRESS_FAMILY)
	{
		family = AF_INET;
		length = sizeof(struct sockaddr_in);
	}
	else if (_family == IP_V6_ADDRESS_FAMILY)
	{
		family = AF_INET6;
		length = sizeof(struct sockaddr_in6);
	}
	else
	{
		free(_socket);
		return NULL;
	}

	SOCKET handle = socket(
		family,
		type,
		protocol);

	if (handle == INVALID_SOCKET)
	{
		free(_socket);
		return NULL;
	}

	int result = bind(
		handle,
		(const struct sockaddr*)&address->handle,
		length);
	
	if (result != 0)
	{
		closesocket(handle);
		free(_socket);
		return NULL;
	}

	if (listening == true)
	{
		assert(_type == STREAM_SOCKET_TYPE);

		result = listen(
			handle,
			SOMAXCONN);

		if (result != 0)
		{
			closesocket(handle);
			free(_socket);
			return NULL;
		}
	}

	if (blocking == false)
	{
#if __linux__ || __APPLE__
		int flags = fcntl(
			handle,
			F_GETFL,
			0);

		if (flags == -1)
		{
			closesocket(handle);
			free(_socket);
			return NULL;
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
			free(_socket);
			return NULL;
		}
	}

	_socket->handle = handle;
	_socket->listening = listening;
	_socket->blocking = blocking;

#if MPNW_HAS_OPENSSL
	if (sslContext != NULL)
	{
		SSL* ssl = SSL_new(
			sslContext->handle);

		if (ssl == NULL)
		{
			closesocket(handle);
			free(_socket);
			return NULL;
		}

		result = SSL_set_fd(
			ssl,
			(int)handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(_socket);
			return NULL;
		}

		_socket->sslContext = sslContext;
		_socket->ssl = ssl;
	}
	else
	{
		_socket->sslContext = NULL;
	}
#endif

	return _socket;
}

void destroySocket(Socket* socket)
{
	assert(isNetworkInitialized() == true);

	if (socket == NULL)
		return;

#if MPNW_HAS_OPENSSL
	if (socket->sslContext != NULL)
		SSL_free(socket->ssl);
#endif

	int result = closesocket(
		socket->handle);

	if (result != 0)
		abort();

	free(socket);
}

uint8_t getSocketType(const Socket* socket)
{
	assert(socket != NULL);

	int type;

	SOCKET_LENGTH length =
		sizeof(int);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_TYPE,
		(char*)&type,
		&length);

	if (result != 0)
		abort();

	if (type == SOCK_STREAM)
		return STREAM_SOCKET_TYPE;
	else if (type == SOCK_DGRAM)
		return DATAGRAM_SOCKET_TYPE;
	else
		return UNKNOWN_SOCKET_TYPE;
}

bool isSocketListening(const Socket* socket)
{
	assert(socket != NULL);
	return socket->listening;
}

bool isSocketBlocking(const Socket* socket)
{
	assert(socket != NULL);
	return socket->blocking;
}

bool getSocketLocalAddress(
	const Socket* socket,
	SocketAddress* address)
{
	assert(socket != NULL);
	assert(address != NULL);

	struct sockaddr_storage socketAddress;

	memset(
		&socketAddress,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getsockname(
		socket->handle,
		(struct sockaddr*)&socketAddress,
		&length);

	if (result == 0)
	{
		address->handle = socketAddress;
		return true;
	}
	else
	{
		return false;
	}
}

bool getSocketRemoteAddress(
	const Socket* socket,
	SocketAddress* address)
{
	assert(socket != NULL);
	assert(address != NULL);

	struct sockaddr_storage socketAddress;

	memset(
		&socketAddress,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&socketAddress,
		&length);

	if (result == 0)
	{
		address->handle = socketAddress;
		return true;
	}
	else
	{
		return false;
	}
}

bool isSocketSsl(const Socket* socket)
{
#if MPNW_HAS_OPENSSL
	assert(socket != NULL);
	return socket->sslContext == NULL;
#else
	abort();
#endif
}

struct SslContext* getSocketSslContext(const Socket* socket)
{
#if MPNW_HAS_OPENSSL
	assert(socket != NULL);
	return socket->sslContext;
#else
	abort();
#endif
}

bool isSocketNoDelay(const Socket* socket)
{
	assert(socket != NULL);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);

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
	Socket* socket,
	bool _value)
{
	assert(socket != NULL);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);

#if __linux__ || __APPLE__
	int value = _value ==
		true ? 1 : 0;
	SOCKET_LENGTH length =
		sizeof(int);
#elif _WIN32
	BOOL value = _value ==
		true ? TRUE : FALSE;
	SOCKET_LENGTH length =
		sizeof(BOOL);
#endif

	int result = setsockopt(
		socket->handle,
		IPPROTO_TCP,
		TCP_NODELAY,
		(char*)&value,
		length);

	if (result != 0)
		abort();
}

Socket* acceptSocket(Socket* socket)
{
	assert(socket != NULL);
	assert(isSocketListening(socket) == true);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);

	Socket* acceptedSocket = malloc(sizeof(Socket));

	if (acceptedSocket == NULL)
		return NULL;

	SOCKET handle = accept(
		socket->handle,
		NULL,
		0);

	if (handle == INVALID_SOCKET)
	{
		free(acceptedSocket);
		return NULL;
	}

	if (socket->blocking == false)
	{
#if __linux__ || __APPLE__
		int flags = fcntl(
			handle,
			F_GETFL,
			0);

		if (flags == -1)
		{
			closesocket(handle);
			free(acceptedSocket);
			return NULL;
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
			free(acceptedSocket);
			return NULL;
		}
	}

	acceptedSocket->handle = handle;
	acceptedSocket->listening = false;
	acceptedSocket->blocking = socket->blocking;

#if MPNW_HAS_OPENSSL
	if (socket->sslContext != NULL)
	{
		SSL* ssl = SSL_new(
			socket->sslContext->handle);

		if (ssl == NULL)
		{
			closesocket(handle);
			free(acceptedSocket);
			return NULL;
		}

		int result = SSL_set_fd(
			ssl,
			(int)handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(acceptedSocket);
			return NULL;
		}

		acceptedSocket->sslContext =
			socket->sslContext;
		acceptedSocket->ssl = ssl;
	}
	else
	{
		acceptedSocket->sslContext = NULL;
	}
#endif

	return acceptedSocket;
}

bool acceptSslSocket(Socket* socket)
{
	assert(socket != NULL);

#if MPNW_HAS_OPENSSL
	assert(socket->sslContext != NULL);

	return SSL_accept(
		socket->ssl) == 1;
#else
	abort();
#endif
}

bool connectSocket(
	Socket* socket,
	const SocketAddress* address)
{
	assert(socket != NULL);
	assert(address != NULL);

	int family = address->handle.ss_family;

	SOCKET_LENGTH length;

	if (family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		return false;

	int result = connect(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length);

	return result == 0 || errno == EISCONN;
}

bool connectSslSocket(Socket* socket)
{
	assert(socket != NULL);

#if MPNW_HAS_OPENSSL
	assert(socket->sslContext != NULL);

	return SSL_connect(
		socket->ssl) == 1;
#else
	abort();
#endif
}

bool shutdownSocket(
	Socket* socket,
	uint8_t _type)
{
	assert(socket != NULL);
	assert(_type < SOCKET_SHUTDOWN_COUNT);

	int type;

#if __linux__ || __APPLE__
	if (_type == RECEIVE_ONLY_SOCKET_SHUTDOWN)
		type = SHUT_RD;
	else if (_type == SEND_ONLY_SOCKET_SHUTDOWN)
		type = SHUT_WR;
	else if (_type == RECEIVE_SEND_SOCKET_SHUTDOWN)
		type = SHUT_RDWR;
	else
		abort();
#elif _WIN32
	if (_type == RECEIVE_ONLY_SOCKET_SHUTDOWN)
		type = SD_RECEIVE;
	else if (_type == SEND_ONLY_SOCKET_SHUTDOWN)
		type = SD_SEND;
	else if (_type == RECEIVE_SEND_SOCKET_SHUTDOWN)
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
	Socket* socket,
	void* buffer,
	size_t size,
	size_t* count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(count != NULL);

#if MPNW_HAS_OPENSSL
	if (socket->sslContext != NULL)
	{
		int result = SSL_read(
			socket->ssl,
			buffer,
			(int)size);

		if (result < 0)
			return false;

		*count = (size_t)result;
		return true;
	}
#endif

	int64_t result = recv(
		socket->handle,
		(char*)buffer,
		(int)size,
		0);

	if (result < 0)
		return false;

	*count = (size_t)result;
	return true;
}

bool socketSend(
	Socket* socket,
	const void* buffer,
	size_t count)
{
	assert(socket != NULL);
	assert(buffer != NULL);

#if MPNW_HAS_OPENSSL
	if (socket->sslContext != NULL)
	{
		return SSL_write(
			socket->ssl,
			buffer,
			(int)count) == count;
	}
#endif

	return send(
		socket->handle,
		(const char*)buffer,
		(int)count,
		0) == count;
}

bool socketReceiveFrom(
	Socket* socket,
	void* buffer,
	size_t size,
	SocketAddress* address,
	size_t* _count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(address != NULL);
	assert(_count != NULL);

#if MPNW_HAS_OPENSSL
	assert(socket->sslContext == NULL);
#endif

	struct sockaddr_storage socketAddress;

	memset(
		&socketAddress,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int64_t count = recvfrom(
		socket->handle,
		(char*)buffer,
		(int)size,
		0,
		(struct sockaddr*)&socketAddress,
		&length);

	if (count < 0)
		return false;

	address->handle = socketAddress;
	*_count = (size_t)count;
	return true;
}

bool socketSendTo(
	Socket* socket,
	const void* buffer,
	size_t count,
	const SocketAddress* address)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(address != NULL);

#if MPNW_HAS_OPENSSL
	assert(socket->sslContext == NULL);
#endif

	SOCKET_LENGTH length;

	if (address->handle.ss_family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if(address->handle.ss_family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		return false;

	return sendto(
		socket->handle,
		(const char*)buffer,
		(int)count,
		0,
		(const struct sockaddr*)&address->handle,
		length) == count;
}

SocketAddress* createSocketAddress(
	const char* host,
	const char* service)
{
	assert(host != NULL);
	assert(service != NULL);
	assert(networkInitialized == true);

	SocketAddress* address = malloc(
		sizeof(SocketAddress));

	if (address == NULL)
		return NULL;

	struct addrinfo hints;

	memset(
		&hints,
		0,
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
		free(address);
		return NULL;
	}

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));
	memcpy(
		&address->handle,
		addressInfos->ai_addr,
		addressInfos->ai_addrlen);

	freeaddrinfo(addressInfos);
	return address;
}

SocketAddress* createEmptySocketAddress()
{
	SocketAddress* address = malloc(
		sizeof(SocketAddress));

	if (address == NULL)
		return NULL;

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

	return address;
}

SocketAddress* resolveSocketAddress(
	const char* host,
	const char* service,
	uint8_t family,
	uint8_t type)
{
	assert(networkInitialized == true);
	assert(host != NULL);
	assert(service != NULL);
	assert(family < ADDRESS_FAMILY_COUNT);
	assert(type < SOCKET_TYPE_COUNT);

	SocketAddress* address = malloc(
		sizeof(SocketAddress));

	if (address == NULL)
		return NULL;

	struct addrinfo hints;

	memset(
		&hints,
		0,
		sizeof(struct addrinfo));

	hints.ai_flags =
		AI_ADDRCONFIG |
		AI_V4MAPPED;

	if(family == IP_V4_ADDRESS_FAMILY)
	{
		hints.ai_family = AF_INET;
	}
	else if(family == IP_V6_ADDRESS_FAMILY)
	{
		hints.ai_family = AF_INET6;
	}
	else
	{
		free(address);
		return NULL;
	}

	if(type == STREAM_SOCKET_TYPE)
	{
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
	else if(type == DATAGRAM_SOCKET_TYPE)
	{
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}
	else
	{
		free(address);
		return NULL;
	}

	struct addrinfo* addressInfos;

	int result = getaddrinfo(
		host,
		service,
		&hints,
		&addressInfos);

	if (result != 0)
	{
		free(address);
		return NULL;
	}

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));
	memcpy(
		&address->handle,
		addressInfos->ai_addr,
		addressInfos->ai_addrlen);

	freeaddrinfo(addressInfos);
	return address;
}

void destroySocketAddress(
	SocketAddress* address)
{
	free(address);
}

SocketAddress* copySocketAddress(
	const SocketAddress* address)
{
	assert(address != NULL);

	SocketAddress* _address = malloc(
		sizeof(SocketAddress));

	if (_address == NULL)
		return NULL;

	memcpy(
		&_address->handle,
		&address->handle,
		sizeof(struct sockaddr_storage));

	return _address;
}

int compareSocketAddress(
	const SocketAddress* a,
	const SocketAddress* b)
{
	assert(a != NULL);
	assert(b != NULL);

	if (a->handle.ss_family == AF_INET)
	{
		return memcmp(
			&a->handle,
			&b->handle,
			sizeof(struct sockaddr_in));
	}
	else if (a->handle.ss_family == AF_INET6)
	{
		return memcmp(
			&a->handle,
			&b->handle,
			sizeof(struct sockaddr_in6));
	}
	else
	{
		return memcmp(
			&a->handle,
			&b->handle,
			sizeof(struct sockaddr_storage));
	}
}

uint8_t getSocketAddressFamily(
	const SocketAddress* address)
{
	assert(address != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
		return IP_V4_ADDRESS_FAMILY;
	else if (family == AF_INET6)
		return IP_V6_ADDRESS_FAMILY;
	else
		return UNKNOWN_ADDRESS_FAMILY;
}

void setSocketAddressFamily(
	SocketAddress* address,
	uint8_t addressFamily)
{
	assert(address != NULL);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
		address->handle.ss_family = AF_INET;
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
		address->handle.ss_family = AF_INET6;
	else
		address->handle.ss_family = AF_UNSPEC;
}

size_t getSocketAddressFamilyIpSize(
	uint8_t addressFamily)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
		return sizeof(struct sockaddr_in);
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
		return sizeof(struct sockaddr_in6);
	else
		return 0;
}

size_t getSocketAddressIpSize(
	const SocketAddress* address)
{
	assert(address != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
		return sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		return sizeof(struct sockaddr_in6);
	else
		return 0;
}

bool getSocketAddressIP(
	const SocketAddress* address,
	uint8_t* ip)
{
	assert(address != NULL);
	assert(ip != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		memcpy(
			ip,
			(const struct sockaddr_in*)&address->handle,
			sizeof(struct sockaddr_in));
		return true;
	}
	else if (family == AF_INET6)
	{
		memcpy(
			ip,
			(const struct sockaddr_in6*)&address->handle,
			sizeof(struct sockaddr_in6));
		return true;
	}
	else
	{
		return false;
	}
}

bool setSocketAddressIP(
	SocketAddress* address,
	const uint8_t* ip,
	size_t size)
{
	assert(address != NULL);
	assert(ip != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET && size == sizeof(struct sockaddr_in))
	{
		memcpy(
			(struct sockaddr_in*)&address->handle,
			ip,
			sizeof(struct sockaddr_in));
		return true;
	}
	else if (family == AF_INET6 && size == sizeof(struct sockaddr_in6))
	{
		memcpy(
			(struct sockaddr_in6*)&address->handle,
			ip,
			sizeof(struct sockaddr_in6));
		return true;
	}
	else
	{
		return false;
	}
}

bool getSocketAddressPort(
	const SocketAddress* address,
	uint16_t* port)
{
	assert(address != NULL);
	assert(port != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&address->handle;
		*port = ntohs(address4->sin_port);
		return true;
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		*port = ntohs(address6->sin6_port);
		return true;
	}
	else
	{
		return false;
	}
}

bool setSocketAddressPort(
	struct SocketAddress* address,
	uint16_t port)
{
	assert(address != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&address->handle;
		address4->sin_port = htons(port);
		return true;
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		address6->sin6_port = htons(port);
		return true;
	}
	else
	{
		return false;
	}
}

bool getSocketAddressHost(
	const SocketAddress* address,
	char* host,
	size_t length)
{
	assert(address != NULL);
	assert(host != NULL);
	assert(length != 0);

	int flags = NI_NUMERICHOST;

	return getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		host,
		(SOCKET_LENGTH)length,
		NULL,
		0,
		flags) == 0;
}

bool getSocketAddressService(
	const SocketAddress* address,
	char* service,
	size_t length)
{
	assert(address != NULL);
	assert(service != NULL);
	assert(length != 0);

	int flags = NI_NUMERICSERV;

	return getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		NULL,
		0,
		service,
		(SOCKET_LENGTH)length,
		flags) == 0;
}

bool getSocketAddressHostService(
	const SocketAddress* address,
	char* host,
	size_t hostLength,
	char* service,
	size_t serviceLength)
{
	assert(address != NULL);
	assert(host != NULL);
	assert(hostLength != 0);
	assert(service != NULL);
	assert(serviceLength != 0);

	int flags =
		NI_NUMERICHOST |
		NI_NUMERICSERV;

	return getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		host,
		(SOCKET_LENGTH)hostLength,
		service,
		(SOCKET_LENGTH)serviceLength,
		flags) == 0;
}

SslContext* createSslContext(
	uint8_t securityProtocol,
	const char* certificateVerifyPath)
{
#if MPNW_HAS_OPENSSL
	assert(networkInitialized == true);
	assert(securityProtocol < SECURITY_PROTOCOL_COUNT);

	SslContext* context = malloc(
		sizeof(SslContext));

	if (context == NULL)
		return NULL;

	SSL_CTX* handle;

	switch (securityProtocol)
	{
	default:
		free(context);
		return NULL;
	case TLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case DTLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(DTLS_method());
		break;
	case TLS_1_2_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
	case DTLS_1_2_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(DTLSv1_2_method());
		break;
	}

	if (handle == NULL)
	{
		free(context);
		return NULL;
	}

	int result;

	if (certificateVerifyPath != NULL)
	{
		result = SSL_CTX_load_verify_locations(
			handle,
			NULL,
			certificateVerifyPath);
	}
	else
	{
		result = SSL_CTX_set_default_verify_paths(
			handle);
	}

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(context);
		return NULL;
	}

	context->handle = handle;
	return context;
#else
	abort();
#endif
}

SslContext* createSslContextFromFile(
	uint8_t securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain)
{
#if MPNW_HAS_OPENSSL
	assert(networkInitialized == true);
	assert(securityProtocol < SECURITY_PROTOCOL_COUNT);
	assert(certificateFilePath != NULL);
	assert(privateKeyFilePath != NULL);

	SslContext* context = malloc(
		sizeof(SslContext));

	if (context == NULL)
		return NULL;

	SSL_CTX* handle;

	switch (securityProtocol)
	{
	default:
		free(context);
		return NULL;
	case TLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case DTLS_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(DTLS_method());
		break;
	case TLS_1_2_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
	case DTLS_1_2_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(DTLSv1_2_method());
		break;
	}

	if (handle == NULL)
	{
		free(context);
		return NULL;
	}

	int result;

	if (certificateChain == true)
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
		free(context);
		return NULL;
	}

	result = SSL_CTX_use_PrivateKey_file(
		handle,
		privateKeyFilePath,
		SSL_FILETYPE_PEM);

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(context);
		return NULL;
	}

	result = SSL_CTX_check_private_key(
		handle);

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(context);
		return NULL;
	}

	context->handle = handle;
	return context;
#else
	abort();
#endif
}

void destroySslContext(SslContext* context)
{
#if MPNW_HAS_OPENSSL
	if (context == NULL)
		return;

	SSL_CTX_free(context->handle);
	free(context);
#else
	abort();
#endif
}

uint8_t getSslContextSecurityProtocol(
	const SslContext* context)
{
#if MPNW_HAS_OPENSSL
	assert(context != NULL);

	const SSL_METHOD* method = SSL_CTX_get_ssl_method(
		context->handle);

	if (method == TLS_method())
		return TLS_SECURITY_PROTOCOL;
	else if (method == DTLS_method())
		return DTLS_SECURITY_PROTOCOL;
	else if (method == TLSv1_2_method())
		return TLS_1_2_SECURITY_PROTOCOL;
	else if (method == DTLSv1_2_method())
		return DTLS_1_2_SECURITY_PROTOCOL;
	else
		return UNKNOWN_SECURITY_PROTOCOL;
#else
	abort();
#endif
}
