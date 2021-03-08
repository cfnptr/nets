#include "mpnw/socket.h"
#include "mpnw/defines.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if __linux__ || __APPLE__
#include <netdb.h>
#include <fcntl.h>
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
	struct SslContext* sslContext;
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

struct Socket* createSocket(
	uint8_t _type,
	uint8_t _family,
	const struct SocketAddress* address,
	bool listening,
	bool blocking,
	struct SslContext* sslContext)
{
	assert(networkInitialized == true);

#if !MPNW_HAS_OPENSSL
	assert(sslContext == NULL);
#endif

	struct Socket* _socket = malloc(
		sizeof(struct Socket));

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
		abort();
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
		abort();
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
		_socket->ssl = NULL;
	}
#endif

	return _socket;
}

void destroySocket(
	struct Socket* socket)
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

uint8_t getSocketType(
	const struct Socket* socket)
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
		abort();
}

bool isSocketListening(
	const struct Socket* socket)
{
	assert(socket != NULL);
	return socket->listening;
}

bool isSocketBlocking(
	const struct Socket* socket)
{
	assert(socket != NULL);
	return socket->blocking;
}

bool getSocketLocalAddress(
	const struct Socket* socket,
	struct SocketAddress* address)
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
	const struct Socket* socket,
	struct SocketAddress* address)
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

bool isSocketSsl(
	const struct Socket* socket)
{
#if MPNW_HAS_OPENSSL
	assert(socket != NULL);
	return socket->sslContext == NULL;
#else
	abort();
#endif
}

struct SslContext* getSocketSslContext(
	const struct Socket* socket)
{
#if MPNW_HAS_OPENSSL
	assert(socket != NULL);
	return socket->sslContext;
#else
	abort();
#endif
}

bool isSocketNoDelay(
	const struct Socket* socket)
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
	struct Socket* socket,
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

bool acceptSocket(
	struct Socket* socket,
	struct Socket** _acceptedSocket)
{
	assert(socket != NULL);
	assert(_acceptedSocket != NULL);
	assert(isSocketListening(socket) == true);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);

	struct Socket* acceptedSocket = malloc(
		sizeof(struct Socket));

	if (acceptedSocket == NULL)
		return false;

	SOCKET handle = accept(
		socket->handle,
		NULL,
		0);

	if (handle == INVALID_SOCKET)
	{
		free(acceptedSocket);
		return false;
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
			return false;
		}

		int result = SSL_set_fd(
			ssl,
			(int)handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(acceptedSocket);
			return false;
		}

		result = SSL_accept(ssl);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(acceptedSocket);
			return false;
		}

		acceptedSocket->sslContext =
			socket->sslContext;
		acceptedSocket->ssl = ssl;
	}
	else
	{
		acceptedSocket->sslContext = NULL;
		acceptedSocket->ssl = NULL;
	}
#endif

	*_acceptedSocket = acceptedSocket;
	return true;
}

bool connectSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
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
		abort();

	int result = connect(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length);

#if MPNW_HAS_OPENSSL
	if (result != 0)
		return false;

	return SSL_connect(
		socket->ssl) == 1;
#else
	return result == 0;
#endif
}

bool shutdownSocket(
	struct Socket* socket,
	uint8_t _type)
{
	assert(socket != NULL);

#if MPNW_HAS_OPENSSL
	if (socket->sslContext != NULL)
		SSL_shutdown(socket->ssl);
#endif

	int type;

#if __linux__ || __APPLE__
	if (_type == SHUTDOWN_RECEIVE_ONLY)
		type = SHUT_RD;
	else if (_type == SHUTDOWN_SEND_ONLY)
		type = SHUT_WR;
	else if (_type == SHUTDOWN_RECEIVE_SEND)
		type = SHUT_RDWR;
	else
		abort();
#elif _WIN32
	if (_type == SHUTDOWN_RECEIVE_ONLY)
		type = SD_RECEIVE;
	else if (_type == SHUTDOWN_SEND_ONLY)
		type = SD_SEND;
	else if (_type == SHUTDOWN_RECEIVE_SEND)
		type = SD_BOTH;
	else
		abort();
#endif

	return shutdown(
		socket->handle,
		type) == 0;
}

bool socketReceive(
	struct Socket* socket,
	void* buffer,
	size_t size,
	size_t* _count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(_count != NULL);

	int count;

#if MPNW_HAS_OPENSSL
	if (socket->sslContext != NULL)
	{
		count = SSL_read(
			socket->ssl,
			buffer,
			(int)size);
	}
	else
	{
		count = recv(
			socket->handle,
			(char*)buffer,
			(int)size,
			0);
	}
#else
	count = recv(
		socket->handle,
		(char*)buffer,
		(int)size,
		0);
#endif

	if (count < 0)
		return false;

	*_count = (size_t)count;
	return true;
}

bool socketSend(
	struct Socket* socket,
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
	else
	{
		return send(
			socket->handle,
			(const char*)buffer,
			(int)count,
			0) == count;
	}
#else
	return send(
		socket->handle,
		(const char*)buffer,
		(int)count,
		0) == count;
#endif
}

bool socketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress* address,
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

	int count = recvfrom(
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
	struct Socket* socket,
	const void* buffer,
	size_t count,
	const struct SocketAddress* address)
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
		abort();

	return sendto(
		socket->handle,
		(const char*)buffer,
		(int)count,
		0,
		(const struct sockaddr*)&address->handle,
		length) == count;
}

struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service)
{
	assert(host != NULL);
	assert(service != NULL);
	assert(networkInitialized == true);

	struct SocketAddress* address = malloc(
		sizeof(struct SocketAddress));

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

struct SocketAddress* resolveSocketAddress(
	const char* host,
	const char* service,
	uint8_t family,
	uint8_t type)
{
	assert(host != NULL);
	assert(service != NULL);
	assert(networkInitialized == true);

	struct SocketAddress* address = malloc(
		sizeof(struct SocketAddress));

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
		hints.ai_family = AF_INET;
	else if(family == IP_V6_ADDRESS_FAMILY)
		hints.ai_family = AF_INET6;
	else
		abort();

	if(type == STREAM_SOCKET_TYPE)
		hints.ai_socktype = SOCK_STREAM;
	else if(type == DATAGRAM_SOCKET_TYPE)
		hints.ai_socktype = SOCK_DGRAM;
	else
		abort();

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
	struct SocketAddress* address)
{
	free(address);
}

struct SocketAddress* copySocketAddress(
	const struct SocketAddress* address)
{
	assert(address != NULL);

	struct SocketAddress* _address = malloc(
		sizeof(struct SocketAddress));

	if (_address == NULL)
		return NULL;

	memcpy(
		&_address->handle,
		&address->handle,
		sizeof(struct sockaddr_storage));

	return _address;
}

int compareSocketAddress(
	const struct SocketAddress* a,
	const struct SocketAddress* b)
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
	const struct SocketAddress* address)
{
	assert(address != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
		return IP_V4_ADDRESS_FAMILY;
	else if (family == AF_INET6)
		return IP_V6_ADDRESS_FAMILY;
	else
		abort();
}

uint8_t* getSocketAddressIP(
	const struct SocketAddress* address,
	size_t* size)
{
	assert(address != NULL);
	assert(size != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		uint8_t* ip = malloc(
			sizeof(struct sockaddr_in));

		if (ip == NULL)
			return NULL;

		const struct sockaddr_in* address4 =
			(const struct sockaddr_in*)&address->handle;

		memcpy(
			ip,
			address4,
			sizeof(struct sockaddr_in));

		*size = sizeof(struct sockaddr_in);
		return ip;
	}
	else if (family == AF_INET6)
	{
		uint8_t* ip = malloc(
			sizeof(struct sockaddr_in6));

		if (ip == NULL)
			return NULL;

		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;

		memcpy(
			ip,
			address6,
			sizeof(struct sockaddr_in6));

		*size = sizeof(struct sockaddr_in6);
		return ip;
	}
	else
	{
		abort();
	}
}

uint16_t getSocketAddressPort(
	const struct SocketAddress* address)
{
	assert(address != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&address->handle;
		return ntohs(address4->sin_port);
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		return ntohs(address6->sin6_port);
	}
	else
	{
		abort();
	}
}

size_t getSocketMaxHostLength()
{
	return NI_MAXHOST;
}

size_t getSocketMaxServiceLength()
{
	return NI_MAXSERV;
}

bool getSocketAddressHost(
	const struct SocketAddress* address,
	char* host)
{
	assert(address != NULL);
	assert(host != NULL);

	int flags = NI_NUMERICHOST;

	return getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		host,
		NI_MAXHOST,
		NULL,
		0,
		flags) == 0;
}

bool getSocketAddressService(
	const struct SocketAddress* address,
	char* service)
{
	assert(address != NULL);
	assert(service != NULL);

	int flags = NI_NUMERICSERV;

	return getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		NULL,
		0,
		service,
		NI_MAXSERV,
		flags) == 0;
}

bool getSocketAddressHostService(
	const struct SocketAddress* address,
	char* host,
	char* service)
{
	assert(address != NULL);
	assert(host != NULL);
	assert(service != NULL);

	int flags =
		NI_NUMERICHOST |
		NI_NUMERICSERV;

	return getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		host,
		NI_MAXHOST,
		service,
		NI_MAXSERV,
		flags) == 0;
}

struct SslContext* createSslContext(
	uint8_t securityProtocol,
	const char* certificateVerifyPath)
{
#if MPNW_HAS_OPENSSL
	assert(networkInitialized == true);

	struct SslContext* context = malloc(
		sizeof(struct SslContext));

	if (context == NULL)
		return NULL;

	SSL_CTX* handle;

	switch (securityProtocol)
	{
	default:
		abort();
	case TLS_1_3_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case DTLS_1_3_SECURITY_PROTOCOL:
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

struct SslContext* createSslContextFromFile(
	uint8_t securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath)
{
#if MPNW_HAS_OPENSSL
	assert(networkInitialized == true);
	assert(certificateFilePath != NULL);
	assert(privateKeyFilePath != NULL);

	struct SslContext* context = malloc(
		sizeof(struct SslContext));

	if (context == NULL)
		return NULL;

	SSL_CTX* handle;

	switch (securityProtocol)
	{
	default:
		abort();
	case TLS_1_3_SECURITY_PROTOCOL:
		handle = SSL_CTX_new(TLS_method());
		break;
	case DTLS_1_3_SECURITY_PROTOCOL:
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

	int result = SSL_CTX_use_certificate_file(
		handle,
		certificateFilePath,
		SSL_FILETYPE_PEM);

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

void destroySslContext(
	struct SslContext* context)
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
	const struct SslContext* context)
{
#if MPNW_HAS_OPENSSL
	assert(context != NULL);

	const SSL_METHOD* method = SSL_CTX_get_ssl_method(
		context->handle);

	if (method == TLS_method())
		return TLS_1_3_SECURITY_PROTOCOL;
	else if (method == DTLS_method())
		return DTLS_1_3_SECURITY_PROTOCOL;
	else if (method == TLSv1_2_method())
		return TLS_1_2_SECURITY_PROTOCOL;
	else if (method == DTLSv1_2_method())
		return DTLS_1_2_SECURITY_PROTOCOL;
	else
		abort();
#else
	abort();
#endif
}

uint16_t hostToNet16(uint16_t value)
{
	return htons(value);
}

uint32_t hostToNet32(uint32_t value)
{
	return htonl(value);
}

uint16_t netToHost16(uint16_t value)
{
	return ntohs(value);
}

uint32_t netToHost32(uint32_t value)
{
	return ntohl(value);
}
