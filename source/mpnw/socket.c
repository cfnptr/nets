#include "mpnw/socket.h"

#include <stdlib.h>
#include <string.h>

#if __linux__ || __APPLE__
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOCKET int
#define INVALID_SOCKET -1
#elif _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

static WSADATA wsaData;
static bool wsaInitialized = false;
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

struct Socket* createSocket(
	enum SocketType type,
	enum AddressFamily family)
{
#if _WIN32
	if (!wsaInitialized)
	{
		int result = WSAStartup(
			MAKEWORD(2,2),
			&wsaData);

		if(result != 0)
			abort();

		wsaInitialized = true;
	}
#endif

	struct Socket* _socket =
		malloc(sizeof(struct Socket));

	if (!_socket)
		abort();

	SOCKET handle = socket(
		family,
		type,
		0);

	if (handle == INVALID_SOCKET)
		abort();

	_socket->handle = handle;
	return _socket;
}
void destroySocket(
	struct Socket* socket)
{
	if (socket)
	{
		shutdown(
			socket->handle,
			SHUTDOWN_RECEIVE_SEND);

#if __linux__ || __APPLE__
		int result = close(socket->handle);

		if(result != 0)
			abort();
#elif _WIN32
		int result = closesocket(socket->handle);

		if(result != 0)
			abort();
#endif
	}

	free(socket);
}

bool isSocketListening(
	const struct Socket* socket)
{
	if (!socket)
		abort();

	socklen_t length =
		sizeof(bool);

	bool listening;

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_ACCEPTCONN,
		(char*)&listening,
		&length);

	if (result != 0)
		abort();

	return listening;
}

struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket)
{
	if (!socket)
		abort();

	socklen_t length =
		sizeof(struct sockaddr_storage);

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));

	int result = getsockname(
		socket->handle,
		(struct sockaddr*)&handle,
		&length);

	if (result != 0)
		abort();

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (!address)
		abort();

	address->handle = handle;
	return address;
}
struct SocketAddress* getSocketRemoteAddress(
	const struct Socket* socket)
{
	if (!socket)
		abort();

	socklen_t length =
		sizeof(struct sockaddr_storage);

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&handle,
		&length);

	if (result != 0)
		abort();

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (!address)
		abort();

	address->handle = handle;
	return address;
}

void setSocketBlocking(
	struct Socket* socket,
	bool blocking)
{
	if (!socket)
		abort();

#if __linux__ || __APPLE__
	int flags = fcntl(
		socket->handle,
		F_GETFL,
		0);

	if (flags == -1)
		abort();

	flags = blocking ?
		(flags & ~O_NONBLOCK) :
		(flags | O_NONBLOCK);

	int result = fcntl(
		socket->handle,
		F_SETFL,
		flags);

	if	(result != 0)
		abort();
#elif _WIN32
	u_long mode = blocking ? 0 : 1;

	int result = ioctlsocket(
		socket->handle,
		FIONBIO,
		&mode);

	if(!result)
		abort();
#endif
}

size_t getSocketReceiveTimeout(
	const struct Socket* socket)
{
	if (!socket)
		abort();

#if __linux__ || __APPLE__
	struct timeval timeout;

	socklen_t size =
		sizeof(struct timeval);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		&timeout,
		&size);

	if (result != 0)
		abort();

	return
		timeout.tv_sec * 1000 +
		timeout.tv_usec / 1000;
#elif _WIN32
	int size =
		sizeof(uint32_t);

	uint32_t timeout;

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		(char*)&timeout,
		&size);

	if (result != 0)
		abort();

	return timeout;
#endif
}
void setSocketReceiveTimeout(
	struct Socket* socket,
	size_t _timeout)
{
	if (!socket)
		abort();

#if __linux__ || __APPLE__
	struct timeval timeout;
	timeout.tv_sec = _timeout / 1000;
	timeout.tv_usec = (_timeout % 1000) * 1000;

	int result = setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		&timeout,
		sizeof(struct timeval));

	if (result != 0)
		abort();
#elif _WIN32
	uint32_t timeout =
		(uint32_t)_timeout;

	int result = setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		(const char*)&timeout,
		sizeof(uint32_t));

	if (result != 0)
		abort();
#endif
}

size_t getSocketSendTimeout(
	const struct Socket* socket)
{
	if (!socket)
		abort();

#if __linux__ || __APPLE__
	struct timeval timeout;

	socklen_t size =
		sizeof(struct timeval);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		&timeout,
		&size);

	if (result != 0)
		abort();

	return
		timeout.tv_sec * 1000 +
		timeout.tv_usec / 1000;
#elif _WIN32
	int size =
		sizeof(uint32_t);

	uint32_t timeout;

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		(char*)&timeout,
		&size);

	if (result != 0)
		abort();

	return timeout;
#endif
}
void setSocketSendTimeout(
	struct Socket* socket,
	size_t _timeout)
{
	if (!socket)
		abort();

#if __linux__ || __APPLE__
	struct timeval timeout;
	timeout.tv_sec = _timeout / 1000;
	timeout.tv_usec = (_timeout % 1000) * 1000;

	int result = setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		&timeout,
		sizeof(struct timeval));

	if(!result)
		abort();
#elif _WIN32
	int result = setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		(const char*)&_timeout,
		sizeof(uint32_t));

	if(!result)
		abort();
#endif
}

void bindSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
{
	if (!socket || !address)
		abort();

	int family = address->handle.ss_family;

	socklen_t length;

	if(family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if(family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		abort();

	int result = bind(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length);

	if (result != 0)
		abort();
}
void listenSocket(
	struct Socket* socket)
{
	if (!socket)
		abort();

	int result = listen(
		socket->handle,
		SOMAXCONN);

	if (result != 0)
		abort();
}

bool acceptSocket(
	struct Socket* socket,
	struct Socket** _acceptedSocket,
	struct SocketAddress** _acceptedAddress)
{
	if(!socket ||
		!_acceptedSocket ||
		!_acceptedAddress)
	{
		abort();
	}

	socklen_t length =
		sizeof(struct sockaddr_storage);

	struct sockaddr_storage addressHandle;

	memset(
		&addressHandle,
		0,
		sizeof(struct sockaddr_storage));

	SOCKET socketHandle = accept(
		socket->handle,
		(struct sockaddr*)&addressHandle,
		&length);

	if (socketHandle == INVALID_SOCKET ||
		(addressHandle.ss_family != AF_INET &&
		addressHandle.ss_family != AF_INET6))
	{
		return false;
	}

	struct Socket* acceptSocket =
		malloc(sizeof(struct Socket));
	struct SocketAddress* acceptAddress =
		malloc(sizeof(struct SocketAddress));

	if (!acceptSocket || !acceptAddress)
		abort();

	acceptSocket->handle = socketHandle;
	acceptAddress->handle = addressHandle;

	*_acceptedSocket = acceptSocket;
	*_acceptedAddress = acceptAddress;
	return true;
}
bool connectSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
{
	if (!socket || !address)
		abort();

	int family = address->handle.ss_family;

	socklen_t length;

	if(family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if(family == AF_INET6)
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
	enum SocketShutdown type)
{
	if (!socket)
		abort();

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
	if (!socket ||
		!buffer ||
		!_count ||
		!size)
		abort();

#if __linux__ || __APPLE__
	int count = recv(
		socket->handle,
		buffer,
		size,
		0);
#elif _WIN32
	int count = recv(
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
	size_t size)
{
	if (!socket ||
		!buffer ||
		!size)
		abort();

#if __linux__ || __APPLE__
	return send(
		socket->handle,
		buffer,
		size,
		0) == size;
#elif _WIN32
	return send(
		socket->handle,
		(const char*)buffer,
		(int)size,
		0) == size;
#endif
}

bool socketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress** address,
	size_t* _count)
{
	if (!socket ||
		!buffer ||
		!address ||
		!_count)
		abort();

	socklen_t length =
		sizeof(struct sockaddr_storage);

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));

#if __linux__ || __APPLE__
	int count = recvfrom(
		socket->handle,
		(char*)buffer,
		(int)size,
		0,
		(struct sockaddr*)&handle,
		&length);
#elif _WIN32
	int count = recvfrom(
		socket->handle,
		buffer,
		size,
		0,
		(struct sockaddr*)&handle,
		&length);
#endif

	if (count < 0)
		return false;

	struct SocketAddress* newAddress =
		malloc(sizeof(struct SocketAddress));

	if (!newAddress) 
		abort();

	newAddress->handle = handle;
	*address = newAddress;
	*_count = (size_t)count;
	return true;
}
bool socketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t size,
	const struct SocketAddress* address)
{
	if (!socket ||
		!buffer ||
		!address)
		abort();

#if __linux__ || __APPLE__
	return sendto(
		socket->handle,
		buffer,
		size,
		0,
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage)) == size;
#elif _WIN32
	return sendto(
		socket->handle,
		(const char*)buffer,
		(int)size,
		0,
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage)) == size;
#endif
}

struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service)
{
	if (!host || !service)
		abort();

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (!address)
		abort();

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
		abort();

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));
	memcpy(
		&handle,
		addressInfos->ai_addr,
		addressInfos->ai_addrlen);

	freeaddrinfo(addressInfos);

	address->handle = handle;
	return address;
}
void destroySocketAddress(
	struct SocketAddress* address)
{
	free(address);
}

enum AddressFamily getSocketAddressFamily(
	const struct SocketAddress* address)
{
	if (!address)
		abort();

	int family = address->handle.ss_family;

	if (family != AF_INET &&
		family != AF_INET6)
		abort();

	return (enum AddressFamily)family;
}
void getSocketAddressIP(
	const struct SocketAddress* address,
	char** _ip,
	size_t* size)
{
	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		const struct sockaddr_in* address4 =
			(const struct sockaddr_in*)&address->handle;

		char* ip = malloc(
			sizeof(const struct sockaddr_in));

		if (!ip)
			abort();

		memcpy(
			ip,
			address4,
			sizeof(const struct sockaddr_in));

		*_ip = ip;
		*size = sizeof(const struct sockaddr_in6);
	}
	else if (family == AF_INET6)
	{
		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;

		char* ip = malloc(
			sizeof(const struct sockaddr_in6));

		if (!ip)
			abort();

		memcpy(
			ip,
			address6,
			sizeof(const struct sockaddr_in6));

		*_ip = ip;
		*size = sizeof(const struct sockaddr_in6);
	}
	else
	{
		abort();
	}
}
uint16_t getSocketAddressPort(
	const struct SocketAddress* address)
{
	if (!address)
		abort();

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		const struct sockaddr_in* address4 =
			(const struct sockaddr_in*)&address->handle;
		return (uint16_t)address4->sin_port;
	}
	else if (family == AF_INET6)
	{
		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;
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
	if (!address)
		abort();

	char buffer[NI_MAXHOST];

	int flags =
		NI_NUMERICHOST;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		buffer,
		NI_MAXHOST,
		NULL,
		0,
		flags);

	if (result != 0)
		abort();

	size_t hostLength =
		strlen(buffer);
	char* host = malloc(
		hostLength * sizeof(char));

	if (!host)
		abort();

	memcpy(
		host,
		buffer,
		hostLength * sizeof(char));

	return host;
}
char* getSocketAddressService(
	const struct SocketAddress* address)
{
	if (!address)
		abort();

	char buffer[NI_MAXSERV];

	int flags =
		NI_NUMERICSERV;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		NULL,
		0,
		buffer,
		NI_MAXSERV,
		flags);

	if (result != 0)
		abort();

	size_t serviceLength =
		strlen(buffer);
	char* service = malloc(
		serviceLength * sizeof(char));

	if (!service)
		abort();

	memcpy(
		service,
		buffer,
		serviceLength * sizeof(char));

	return service;
}
void getSocketAddressHostService(
	const struct SocketAddress* address,
	char** _host,
	char** _service)
{
	if (!address ||
		!_host ||
		!_service)
		abort();

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
		abort();

	size_t hostLength =
		strlen(hostBuffer);
	char* host = malloc(
		hostLength * sizeof(char));

	size_t serviceLength =
		strlen(hostBuffer);
	char* service = malloc(
		serviceLength * sizeof(char));

	if (!host || !service)
		abort();

	memcpy(
		host,
		hostBuffer,
		hostLength * sizeof(char));
	memcpy(
		service,
		serviceBuffer,
		serviceLength * sizeof(char));

	*_host = host;
	*_service = service;
}
