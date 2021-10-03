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
#include "openssl/err.h"
#else
#define SSL_CTX void
#endif

struct Socket
{
	SocketType type;
	bool listening;
	bool blocking;
	SOCKET handle;

#if MPNW_SUPPORT_OPENSSL
	SslContext sslContext;
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
	if(networkInitialized == false)
		return;

#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_DFL);
#elif _WIN32
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
	SocketType _type,
	AddressFamily _family,
	SocketAddress address,
	bool listening,
	bool blocking,
	SslContext sslContext,
	Socket* _socket)
{
	assert(_type < SOCKET_TYPE_COUNT);
	assert(_family < ADDRESS_FAMILY_COUNT);
	assert(address != NULL);
	assert(_socket != NULL);
	assert(networkInitialized == true);

#if !MPNW_SUPPORT_OPENSSL
	assert(sslContext == NULL);
#endif

	Socket socketInstance = malloc(
		sizeof(struct Socket));

	if (socketInstance == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

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
		free(socketInstance);
		return FAILED_TO_CREATE_SOCKET_MPNW_RESULT;
	}

	int result = bind(
		handle,
		(const struct sockaddr*)&address->handle,
		length);
	
	if (result != 0)
	{
		closesocket(handle);
		free(socketInstance);
		return FAILED_TO_BIND_SOCKET_MPNW_RESULT;
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
			free(socketInstance);
			return FAILED_TO_LISTEN_SOCKET_MPNW_RESULT;
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

	socketInstance->type = _type;
	socketInstance->listening = listening;
	socketInstance->blocking = blocking;
	socketInstance->handle = handle;

#if MPNW_SUPPORT_OPENSSL
	if (sslContext != NULL)
	{
		SSL* ssl = SSL_new(
			sslContext->handle);

		if (ssl == NULL)
		{
			closesocket(handle);
			free(socketInstance);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		result = SSL_set_fd(
			ssl,
			(int)handle);

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
	assert(networkInitialized == true);

	if (socket == NULL)
		return;

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext != NULL)
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
	assert(socket != NULL);
	assert(networkInitialized == true);
	return socket->type;
}

bool isSocketListening(Socket socket)
{
	assert(socket != NULL);
	assert(networkInitialized == true);
	return socket->listening;
}

bool isSocketBlocking(Socket socket)
{
	assert(socket != NULL);
	assert(networkInitialized == true);
	return socket->blocking;
}

bool getSocketLocalAddress(
	Socket socket,
	SocketAddress address)
{
	assert(socket != NULL);
	assert(address != NULL);
	assert(networkInitialized == true);

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
	Socket socket,
	SocketAddress address)
{
	assert(socket != NULL);
	assert(address != NULL);
	assert(networkInitialized == true);

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

bool isSocketSsl(Socket socket)
{
#if MPNW_SUPPORT_OPENSSL
	assert(socket != NULL);
	assert(networkInitialized == true);
	return socket->sslContext == NULL;
#else
	abort();
#endif
}

SslContext getSocketSslContext(Socket socket)
{
#if MPNW_SUPPORT_OPENSSL
	assert(socket != NULL);
	assert(networkInitialized == true);
	return socket->sslContext;
#else
	abort();
#endif
}

bool isSocketNoDelay(Socket socket)
{
	assert(socket != NULL);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);
	assert(networkInitialized == true);

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
	bool _value)
{
	assert(socket != NULL);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);
	assert(networkInitialized == true);

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

MpnwResult acceptSocket(
	Socket socket,
	Socket* _accepted)
{
	assert(socket != NULL);
	assert(_accepted != NULL);
	assert(isSocketListening(socket) == true);
	assert(getSocketType(socket) == STREAM_SOCKET_TYPE);
	assert(networkInitialized == true);

	Socket accepted = malloc(
		sizeof(struct Socket));

	if (accepted == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

	SOCKET handle = accept(
		socket->handle,
		NULL,
		0);

	if (handle == INVALID_SOCKET)
	{
		free(accepted);
		return FAILED_TO_ACCEPT_SOCKET_MPNW_RESULT;
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
			free(accepted);
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
			free(accepted);
			return FAILED_TO_SET_SOCKET_FLAG_MPNW_RESULT;
		}
	}

	accepted->type = socket->type;
	accepted->listening = false;
	accepted->blocking = socket->blocking;
	accepted->handle = handle;

#if MPNW_SUPPORT_OPENSSL
	if (socket->sslContext != NULL)
	{
		SSL* ssl = SSL_new(
			socket->sslContext->handle);

		if (ssl == NULL)
		{
			closesocket(handle);
			free(accepted);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		int result = SSL_set_fd(
			ssl,
			(int)handle);

		if (result != 1)
		{
			SSL_free(ssl);
			closesocket(handle);
			free(accepted);
			return FAILED_TO_CREATE_SSL_MPNW_RESULT;
		}

		accepted->sslContext =
			socket->sslContext;
		accepted->ssl = ssl;
	}
	else
	{
		accepted->sslContext = NULL;
	}
#endif

	*_accepted = accepted;
	return SUCCESS_MPNW_RESULT;
}

bool acceptSslSocket(Socket socket)
{
	assert(socket != NULL);
	assert(networkInitialized == true);

#if MPNW_SUPPORT_OPENSSL
	assert(socket->sslContext != NULL);
	return SSL_accept(socket->ssl) == 1;
#else
	abort();
#endif
}

bool connectSocket(
	Socket socket,
	SocketAddress address)
{
	assert(socket != NULL);
	assert(address != NULL);
	assert(networkInitialized == true);

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
	assert(socket != NULL);
	assert(networkInitialized == true);

#if MPNW_SUPPORT_OPENSSL
	assert(socket->sslContext != NULL);
	return SSL_connect(socket->ssl) == 1;
#else
	abort();
#endif
}

bool shutdownSocket(
	Socket socket,
	SocketShutdown _type)
{
	assert(socket != NULL);
	assert(_type < SOCKET_SHUTDOWN_COUNT);
	assert(networkInitialized == true);

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
	Socket socket,
	void* buffer,
	size_t size,
	size_t* count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(size != 0);
	assert(count != NULL);
	assert(networkInitialized == true);

#if MPNW_SUPPORT_OPENSSL
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
	Socket socket,
	const void* buffer,
	size_t count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(networkInitialized == true);

#if MPNW_SUPPORT_OPENSSL
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
	Socket socket,
	SocketAddress address,
	void* buffer,
	size_t size,
	size_t* _count)
{
	assert(socket != NULL);
	assert(address != NULL);
	assert(buffer != NULL);
	assert(size != 0);
	assert(_count != NULL);
	assert(networkInitialized == true);

#if MPNW_SUPPORT_OPENSSL
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
	Socket socket,
	const void* buffer,
	size_t count,
	SocketAddress address)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(address != NULL);
	assert(networkInitialized == true);

#if MPNW_SUPPORT_OPENSSL
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

MpnwResult createSocketAddress(
	const char* host,
	const char* service,
	SocketAddress* _address)
{
	assert(host != NULL);
	assert(service != NULL);
	assert(_address != NULL);
	assert(networkInitialized == true);

	SocketAddress address = malloc(
		sizeof(struct SocketAddress));

	if (address == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

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
		return FAILED_TO_GET_ADDRESS_INFO_MPNW_RESULT;
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

	*_address = address;
	return SUCCESS_MPNW_RESULT;
}

SocketAddress createSocketAddressCopy(
	SocketAddress address)
{
	assert(address != NULL);

	SocketAddress _address = malloc(
		sizeof(struct SocketAddress));

	if (_address == NULL)
		return NULL;

	memcpy(
		&_address->handle,
		&address->handle,
		sizeof(struct sockaddr_storage));

	return _address;
}

MpnwResult resolveSocketAddress(
	const char* host,
	const char* service,
	AddressFamily family,
	SocketType type,
	SocketAddress* _address)
{
	assert(host != NULL);
	assert(service != NULL);
	assert(family < ADDRESS_FAMILY_COUNT);
	assert(type < SOCKET_TYPE_COUNT);
	assert(_address != NULL);
	assert(networkInitialized == true);

	SocketAddress address = malloc(
		sizeof(struct SocketAddress));

	if (address == NULL)
		return FAILED_TO_ALLOCATE_MPNW_RESULT;

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
		abort();
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
		free(address);
		return FAILED_TO_GET_ADDRESS_INFO_MPNW_RESULT;
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

	*_address = address;
	return SUCCESS_MPNW_RESULT;
}

void destroySocketAddress(SocketAddress address)
{
	assert(networkInitialized == true);

	if (address == NULL)
		return;

	free(address);
}

void copySocketAddress(
	SocketAddress sourceAddress,
	SocketAddress destinationAddress)
{
	assert(sourceAddress != NULL);
	assert(destinationAddress != NULL);

	memcpy(
		&destinationAddress->handle,
		&sourceAddress->handle,
		sizeof(struct sockaddr_storage));
}

int compareSocketAddress(
	SocketAddress a,
	SocketAddress b)
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

AddressFamily getSocketAddressFamily(
	SocketAddress address)
{
	assert(address != NULL);
	assert(networkInitialized == true);

	int family = address->handle.ss_family;

	if (family == AF_INET)
		return IP_V4_ADDRESS_FAMILY;
	else if (family == AF_INET6)
		return IP_V6_ADDRESS_FAMILY;
	else
		abort();
}

void setSocketAddressFamily(
	SocketAddress address,
	AddressFamily addressFamily)
{
	assert(address != NULL);
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(networkInitialized == true);

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
		address->handle.ss_family = AF_INET;
	else
		address->handle.ss_family = AF_INET6;
}

size_t getSocketAddressFamilyIpSize(
	AddressFamily addressFamily)
{
	assert(addressFamily < ADDRESS_FAMILY_COUNT);
	assert(networkInitialized == true);

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
		return sizeof(struct sockaddr_in);
	else
		return sizeof(struct sockaddr_in6);
}

size_t getSocketAddressIpSize(
	SocketAddress address)
{
	assert(address != NULL);
	assert(networkInitialized == true);

	int family = address->handle.ss_family;

	if (family == AF_INET)
		return sizeof(struct sockaddr_in);
	else
		return sizeof(struct sockaddr_in6);
}

const uint8_t* getSocketAddressIp(
	SocketAddress address)
{
	assert(address != NULL);
	assert(networkInitialized == true);
	return (const uint8_t*)&address->handle;
}

bool setSocketAddressIp(
	SocketAddress address,
	const uint8_t* ip,
	size_t size)
{
	assert(address != NULL);
	assert(ip != NULL);
	assert(networkInitialized == true);

	int family = address->handle.ss_family;

	if (family == AF_INET && size == sizeof(struct sockaddr_in))
	{
		memcpy(
			(struct sockaddr_in*)&address->handle,
			ip,
			sizeof(struct sockaddr_in));
		return true;
	}
	else if (size == sizeof(struct sockaddr_in6))
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

uint16_t getSocketAddressPort(
	SocketAddress address)
{
	assert(address != NULL);
	assert(networkInitialized == true);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&address->handle;
		return ntohs(address4->sin_port);
	}
	else
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		return ntohs(address6->sin6_port);
	}
}

void setSocketAddressPort(
	SocketAddress address,
	uint16_t port)
{
	assert(address != NULL);
	assert(networkInitialized == true);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&address->handle;
		address4->sin_port = htons(port);
	}
	else
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		address6->sin6_port = htons(port);
	}
}

bool getSocketAddressHost(
	SocketAddress address,
	char* host,
	size_t length)
{
	assert(address != NULL);
	assert(host != NULL);
	assert(length != 0);
	assert(networkInitialized == true);

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
	SocketAddress address,
	char* service,
	size_t length)
{
	assert(address != NULL);
	assert(service != NULL);
	assert(length != 0);
	assert(networkInitialized == true);

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
	SocketAddress address,
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
	assert(networkInitialized == true);

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

MpnwResult createPublicSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* certificatesDirectory,
	SslContext* _sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	assert(securityProtocol < SECURITY_PROTOCOL_COUNT);
	assert(_sslContext != NULL);
	assert(networkInitialized == true);

	SslContext sslContext = malloc(
		sizeof(struct SslContext));

	if (sslContext == NULL)
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
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
	}

	if (handle == NULL)
	{
		free(sslContext);
		return FAILED_TO_CREATE_SSL_MPNW_RESULT;
	}

	int result;

	if (certificateFilePath != NULL ||
		certificatesDirectory != NULL)
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
		free(sslContext);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	sslContext->handle = handle;

	*_sslContext = sslContext;
	return SUCCESS_MPNW_RESULT;
#else
	return NULL;
#endif
}

MpnwResult createPrivateSslContext(
	SecurityProtocol securityProtocol,
	const char* certificateFilePath,
	const char* privateKeyFilePath,
	bool certificateChain,
	SslContext* _sslContext)
{
#if MPNW_SUPPORT_OPENSSL
	assert(securityProtocol < SECURITY_PROTOCOL_COUNT);
	assert(certificateFilePath != NULL);
	assert(privateKeyFilePath != NULL);
	assert(_sslContext != NULL);
	assert(networkInitialized == true);

	SslContext sslContext = malloc(
		sizeof(struct SslContext));

	if (sslContext == NULL)
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
		handle = SSL_CTX_new(TLSv1_2_method());
		break;
	}

	if (handle == NULL)
	{
		free(sslContext);
		return FAILED_TO_CREATE_SSL_MPNW_RESULT;
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
		free(sslContext);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	result = SSL_CTX_use_PrivateKey_file(
		handle,
		privateKeyFilePath,
		SSL_FILETYPE_PEM);

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(sslContext);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	result = SSL_CTX_check_private_key(handle);

	if (result != 1)
	{
		SSL_CTX_free(handle);
		free(sslContext);
		return FAILED_TO_LOAD_CERTIFICATE_MPNW_RESULT;
	}

	sslContext->handle = handle;

	*_sslContext = sslContext;
	return SUCCESS_MPNW_RESULT;
#else
	return NULL;
#endif
}

void destroySslContext(SslContext context)
{
#if MPNW_SUPPORT_OPENSSL
	assert(networkInitialized == true);

	if (context == NULL)
		return;

	SSL_CTX_free(context->handle);
	free(context);
#else
	abort();
#endif
}

SecurityProtocol getSslContextSecurityProtocol(
	SslContext context)
{
#if MPNW_SUPPORT_OPENSSL
	assert(context != NULL);
	assert(networkInitialized == true);

	const SSL_METHOD* method =
		SSL_CTX_get_ssl_method(context->handle);

	if (method == TLS_method())
		return TLS_SECURITY_PROTOCOL;
	else if (method == TLSv1_2_method())
		return TLS_1_2_SECURITY_PROTOCOL;
	else
		abort();
#else
	abort();
#endif
}
