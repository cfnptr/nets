#include "mpnw/socket.h"

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

#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_LENGTH socklen_t
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

struct Socket
{
	SOCKET handle;
};

struct SocketAddress
{
	struct sockaddr_storage handle;
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

	networkInitialized = true;
	return true;
}
/* Terminates network. */
void terminateNetwork()
{
	if(networkInitialized == true)
		return;

#if __linux__ || __APPLE__
	signal(SIGPIPE, SIG_DFL);
#elif _WIN32
	int result = WSACleanup();

	if (result != 0)
		abort();
#endif

	networkInitialized = false;
}

struct Socket* createSocket(
	enum SocketType _type,
	enum AddressFamily _family)
{
	if(networkInitialized == false)
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

	struct Socket* _socket =
		malloc(sizeof(struct Socket));

	if (_socket == NULL)
		return NULL;

	SOCKET handle = socket(
		family,
		type,
		0);

	if (handle == INVALID_SOCKET)
	{
		free(socket);
		return NULL;
	}

	_socket->handle = handle;
	return _socket;
}

void destroySocket(
	struct Socket* socket)
{
	if (socket == NULL)
		return;

#if __linux__ || __APPLE__
	int result = close(
		socket->handle);
#elif _WIN32
	int result = closesocket(
		socket->handle);
#endif

	if (result != 0)
		abort();

	free(socket);
}

bool getSocketLocalAddress(
	const struct Socket* socket,
	struct SocketAddress** _address)
{
	assert(socket != NULL);
	assert(_address != NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		return false;

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getsockname(
		socket->handle,
		(struct sockaddr*)&handle,
		&length);

	if (result != 0)
	{
		free(address);
		return false;
	}

	address->handle = handle;
	*_address = address;
	return true;
}

bool getSocketRemoteAddress(
	const struct Socket* socket,
	struct SocketAddress** _address)
{
	assert(socket != NULL);
	assert(_address != NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		return false;

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET_LENGTH length =
		sizeof(struct sockaddr_storage);

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&handle,
		&length);

	if (result != 0)
	{
		free(address);
		return false;
	}

	address->handle = handle;
	*_address = address;
	return true;
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
		return false;

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

	struct Socket* acceptedSocket =
		malloc(sizeof(struct Socket));

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
		return false;

	return connect(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length) == 0;
}

bool shutdownSocket(
	struct Socket* socket,
	enum SocketShutdown _type)
{
	assert(socket != NULL);

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
	assert(size > 0);
	assert(_count != NULL);

	int count = recv(
		socket->handle,
		(char*)buffer,
		(int)size,
		0);

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

	return send(
		socket->handle,
		(const char*)buffer,
		(int)count,
		0) == count;
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
	assert(size > 0);
	assert(_address != NULL);
	assert(_count != NULL);

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
	assert(address != NULL);

	return sendto(
		socket->handle,
		(const char*)buffer,
		(int)count,
		0,
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage)) == count;
}

struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service)
{
	assert(host != NULL);
	assert(service != NULL);

	if(networkInitialized == false)
		return NULL;

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

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
	enum AddressFamily family,
	enum SocketType type)
{
	assert(host != NULL);
	assert(service != NULL);

	if(networkInitialized == false)
		return NULL;

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

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

	struct SocketAddress* _address =
		malloc(sizeof(struct SocketAddress));

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

bool getSocketAddressFamily(
	const struct SocketAddress* address,
	enum AddressFamily* _family)
{
	assert(address != NULL);
	assert(_family != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		*_family = IP_V4_ADDRESS_FAMILY;
		return true;
	}
	else if (family == AF_INET6)
	{
		*_family = IP_V6_ADDRESS_FAMILY;
		return true;
	}
	else
	{
		return false;
	}
}

bool getSocketAddressIP(
	const struct SocketAddress* address,
	uint8_t** _ip,
	size_t* size)
{
	assert(address != NULL);
	assert(_ip != NULL);
	assert(size != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		uint8_t* ip = malloc(
			sizeof(struct sockaddr_in));

		if (ip == NULL)
			return false;

		const struct sockaddr_in* address4 =
			(const struct sockaddr_in*)&address->handle;

		memcpy(
			ip,
			address4,
			sizeof(struct sockaddr_in));

		*_ip = ip;
		*size = sizeof(struct sockaddr_in);
		return true;
	}
	else if (family == AF_INET6)
	{
		uint8_t* ip = malloc(
			sizeof(struct sockaddr_in6));

		if (ip == NULL)
			return false;

		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;

		memcpy(
			ip,
			address6,
			sizeof(struct sockaddr_in6));

		*_ip = ip;
		*size = sizeof(struct sockaddr_in6);
		return true;
	}
	else
	{
		return false;
	}
}

bool getSocketAddressPort(
	const struct SocketAddress* address,
	uint16_t* portNumber)
{
	assert(address != NULL);
	assert(portNumber != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		struct sockaddr_in* address4 =
			(struct sockaddr_in*)&address->handle;
		*portNumber = (uint16_t)address4->sin_port;
		return true;
	}
	else if (family == AF_INET6)
	{
		struct sockaddr_in6* address6 =
			(struct sockaddr_in6*)&address->handle;
		*portNumber = (uint16_t)address6->sin6_port;
		return true;
	}
	else
	{
		return false;
	}
}

bool getSocketAddressHost(
	const struct SocketAddress* address,
	char** _host)
{
	assert(address != NULL);
	assert(_host != NULL);

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
		return false;

	size_t hostLength =
		strlen(buffer) * sizeof(char);
	char* host = malloc(
		hostLength);

	if (host == NULL)
		return false;

	memcpy(
		host,
		buffer,
		hostLength);

	*_host = host;
	return host;
}

bool getSocketAddressService(
	const struct SocketAddress* address,
	char** _service)
{
	assert(address != NULL);
	assert(_service != NULL);

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
		return false;

	size_t serviceLength =
		strlen(buffer) * sizeof(char);
	char* service = malloc(
		serviceLength);

	if (service == NULL)
		return false;

	memcpy(
		service,
		buffer,
		serviceLength);

	*_service = service;
	return true;
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
