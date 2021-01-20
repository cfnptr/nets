#include "mpnw/socket.h"
#include "mpnw/defines.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if __linux__ || __APPLE__
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
#define SSL void
#endif

struct Socket
{
	SOCKET handle;
	SSL* ssl;
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
	OpenSSL_add_all_algorithms();
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
bool getNetworkInitialized()
{
	return networkInitialized;
}

struct Socket* createSocket(
	uint8_t _type,
	uint8_t _family,
	struct SslContext* sslContext)
{
	assert(networkInitialized == true);

#if MPNW_HAS_OPENSSL
#ifndef NDEBUG
	if (sslContext != NULL)
	{
		if (_type == STREAM_SOCKET_TYPE)
		{
			assert(SSL_CTX_get_ssl_method(
				sslContext->handle) == TLS_method());
		}
		else if (_type == DATAGRAM_SOCKET_TYPE)
		{
			assert(SSL_CTX_get_ssl_method(
				sslContext->handle) == DTLS_method());
		}
		else
		{
			abort();
		}
	}
#endif
#else
	assert(sslContext == NULL);
#endif

	struct Socket* _socket = malloc(
		sizeof(struct Socket));

	if (_socket == NULL)
		return NULL;

	int type, family;

	if (_type == STREAM_SOCKET_TYPE)
		type = SOCK_STREAM;
	else if (_type == DATAGRAM_SOCKET_TYPE)
		type = SOCK_DGRAM;
	else
		abort();

	if (_family == IP_V4_ADDRESS_FAMILY)
		family = AF_INET;
	else if (_family == IP_V6_ADDRESS_FAMILY)
		family = AF_INET6;
	else
		abort();

	SOCKET handle = socket(
		family,
		type,
		0);

	if (handle == INVALID_SOCKET)
	{
		free(_socket);
		return NULL;
	}

	SSL* ssl;

#if MPNW_HAS_OPENSSL
	if (sslContext != NULL)
	{
		ssl = SSL_new(
			sslContext->handle);

		if (ssl == NULL)
		{
			closesocket(handle);
			free(_socket);
			return NULL;
		}

		int result = SSL_set_fd(
			ssl,
			handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(_socket);
			return NULL;
		}
	}
	else
	{
		ssl = NULL;
	}
#else
	ssl = NULL;
#endif

	_socket->handle = handle;
	_socket->ssl = ssl;
	return _socket;
}

void destroySocket(
	struct Socket* socket)
{
	if (socket == NULL)
		return;

#if MPNW_HAS_OPENSSL
	if (socket->ssl != NULL)
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

bool getSocketSSL(
	const struct Socket* socket)
{
	assert(socket != NULL);
	return socket->ssl == NULL;
}

struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket)
{
	assert(socket != NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		return NULL;

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getsockname(
		socket->handle,
		(struct sockaddr*)&address->handle,
		&length);

	if (result != 0)
		abort();

	return address;
}

struct SocketAddress* getSocketRemoteAddress(
	const struct Socket* socket)
{
	assert(socket != NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		return NULL;

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&address->handle,
		&length);

	if (result != 0)
		abort();

	return address;
}

bool bindSocket(
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

	return bind(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length) == 0;
}

bool listenSocket(
	struct Socket* socket)
{
	assert(socket != NULL);

	return listen(
		socket->handle,
		SOMAXCONN) == 0;
}

bool acceptSocket(
	struct Socket* socket,
	struct Socket** _acceptedSocket)
{
	assert(socket != NULL);
	assert(_acceptedSocket != NULL);

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

	SSL* ssl;

#if MPNW_HAS_OPENSSL
	if (socket->ssl != NULL)
	{
		SSL_CTX* context = SSL_get_SSL_CTX(
			socket->ssl);

		if (context == NULL)
		{
			closesocket(handle);
			free(acceptedSocket);
			return false;
		}

		ssl = SSL_new(context);

		if (ssl == NULL)
		{
			closesocket(handle);
			free(acceptedSocket);
			return false;
		}

		int result = SSL_accept(ssl);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(acceptedSocket);
			return false;
		}
	}
	else
	{
		ssl = NULL;
	}
#else
	ssl = NULL;
#endif

	acceptedSocket->handle = handle;
	acceptedSocket->ssl = NULL;
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

	return connect(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length) == 0;
}

bool shutdownSocket(
	struct Socket* socket,
	uint8_t _type)
{
	assert(socket != NULL);

#if MPNW_HAS_OPENSSL
	if (socket->ssl != NULL)
	{
		int result = SSL_shutdown(
			socket->ssl);

		if (result == 0)
			SSL_shutdown(socket->ssl);
	}
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
	assert(size != 0);
	assert(_count != NULL);

	int count;

#if MPNW_HAS_OPENSSL
	if (socket->ssl != NULL)
	{
		count = SSL_read(
			socket->ssl,
			buffer,
			size);
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
	assert(count != 0);

#if MPNW_HAS_OPENSSL
	return SSL_write(
		socket->ssl,
		buffer,
		count) == count;
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
	struct SocketAddress** _address,
	size_t* _count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(size != 0);
	assert(_address != NULL);
	assert(_count != NULL);
	assert(socket->ssl == NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		return false;

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int count = recvfrom(
		socket->handle,
		(char*)buffer,
		(int)size,
		0,
		(struct sockaddr*)&address->handle,
		&length);

	if (count < 0)
	{
		free(address);
		return false;
	}

	*_address = address;
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
	assert(count != 0);
	assert(address != NULL);
	assert(socket->ssl == NULL);

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

	return memcmp(
		&a->handle,
		&b->handle,
		sizeof(struct sockaddr_storage));
}

enum AddressFamily getSocketAddressFamily(
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
		return (uint16_t)address4->sin_port;
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		return (uint16_t)address6->sin6_port;
	}
	else
	{
		abort();
	}
}

char* getSocketAddressHost(
	const struct SocketAddress* address)
{
	assert(address != NULL);

	char buffer[NI_MAXHOST];
	int flags = NI_NUMERICHOST;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		buffer,
		NI_MAXHOST,
		NULL,
		0,
		flags);

	if (result != 0)
		return NULL;

	size_t hostLength =
		strlen(buffer) * sizeof(char);
	char* host = malloc(
		hostLength);

	if (host == NULL)
		return NULL;

	memcpy(
		host,
		buffer,
		hostLength);

	return host;
}

char* getSocketAddressService(
	const struct SocketAddress* address)
{
	assert(address != NULL);

	char buffer[NI_MAXSERV];
	int flags = NI_NUMERICSERV;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		NULL,
		0,
		buffer,
		NI_MAXSERV,
		flags);

	if (result != 0)
		return NULL;

	size_t serviceLength =
		strlen(buffer) * sizeof(char);
	char* service = malloc(
		serviceLength);

	if (service == NULL)
		return NULL;

	memcpy(
		service,
		buffer,
		serviceLength);

	return service;
}

bool getSocketAddressHostService(
	const struct SocketAddress* address,
	char** _host,
	char** _service)
{
	assert(address != NULL);
	assert(_host != NULL);
	assert(_service != NULL);

	char hostBuffer[NI_MAXHOST];
	char serviceBuffer[NI_MAXSERV];

	int flags =
		NI_NUMERICHOST |
		NI_NUMERICSERV;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		hostBuffer,
		NI_MAXHOST,
		serviceBuffer,
		NI_MAXSERV,
		flags);

	if (result != 0)
		return false;

	size_t hostLength =
		strlen(hostBuffer) * sizeof(char);
	char* host = malloc(
		hostLength);

	if (host == NULL)
		return false;

	size_t serviceLength =
		strlen(hostBuffer) * sizeof(char);
	char* service = malloc(
		serviceLength);

	if (service == NULL)
	{
		free(host);
		return false;
	}

	memcpy(
		host,
		hostBuffer,
		hostLength);
	memcpy(
		service,
		serviceBuffer,
		serviceLength);

	*_host = host;
	*_service = service;
	return true;
}

struct SslContext* createSslContextFromFile(
	uint8_t socketType,
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

	if (socketType == STREAM_SOCKET_TYPE)
		handle = SSL_CTX_new(TLS_method());
	else if (socketType == DATAGRAM_SOCKET_TYPE)
		handle = SSL_CTX_new(DTLS_method());
	else
		abort();

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
