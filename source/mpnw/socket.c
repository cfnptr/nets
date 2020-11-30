#include "mpnw/socket.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
	bool blocking;
};

struct SocketAddress
{
	struct sockaddr_storage handle;
};

struct Socket* createSocket(
	enum SocketType _type,
	enum AddressFamily _family)
{
#if _WIN32
	if (wsaInitialized == false)
	{
		int result = WSAStartup(
			MAKEWORD(2,2),
			&wsaData);

		if (result != 0)
			abort();

		wsaInitialized = true;
	}
#endif

	struct Socket* _socket =
		malloc(sizeof(struct Socket));

	if (_socket == NULL)
		abort();

	_socket->blocking = false;

	int type;
	int family;

	if(_type == STREAM_SOCKET)
		type = SOCK_STREAM;
	else if(_type == DATAGRAM_SOCKET)
		type = SOCK_DGRAM;
	else
		abort();

	if(_family == INTERNET_PROTOCOL_V4)
		family = AF_INET;
	else if(_family == INTERNET_PROTOCOL_V6)
		family = AF_INET6;
	else
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
	if (socket != NULL)
	{
		shutdown(
			socket->handle,
			SHUTDOWN_RECEIVE_SEND);

#if __linux__ || __APPLE__
		int result = close(
			socket->handle);

		if (result != 0)
			abort();
#elif _WIN32
		int result = closesocket(
			socket->handle);

		if (result != 0)
			abort();
#endif
	}

	free(socket);
}

enum SocketType getSocketType(
	const struct Socket* socket)
{
	assert(socket != NULL);

	int type;

#if __linux__ || __APPLE__
	socklen_t length =
		sizeof(int);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_TYPE,
		&type,
		&length);
#elif _WIN32
	int length =
		sizeof(int);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_TYPE,
		(char*)&type,
		&length);
#endif

	if (result != 0)
		abort();

	if (type == SOCK_STREAM)
		return STREAM_SOCKET;
	else if (type == SOCK_DGRAM)
		return DATAGRAM_SOCKET;
	else
		abort();
}
bool isSocketListening(
	const struct Socket* socket)
{
	assert(socket != NULL);

#if __linux__ || __APPLE__
	int listening;

	socklen_t length =
		sizeof(int);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_ACCEPTCONN,
		&listening,
		&length);

	if (result != 0)
		abort();

	return listening;
#elif _WIN32
	BOOL listening;

	int length =
		sizeof(BOOL);

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_ACCEPTCONN,
		(char*)&listening,
		&length);

	if (result != 0)
		abort();

	return listening == TRUE;
#endif
}

struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket)
{
	assert(socket != NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		abort();

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

	socklen_t length =
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
		abort();

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

#if __linux__ || __APPLE__
	socklen_t length =
		sizeof(struct sockaddr_storage);

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&address->handle,
		&length);
#elif
	int length =
		sizeof(struct sockaddr_storage);

	int result = getpeername(
		socket->handle,
		(struct sockaddr*)&address->handle,
		&length);
#endif

	if (result != 0)
		abort();

	return address;
}

bool getSocketBlocking(
	const struct Socket* socket)
{
	assert(socket != NULL);
	return socket->blocking;
}
void setSocketBlocking(
	struct Socket* socket,
	bool blocking)
{
	assert(socket != NULL);

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

	if (result != 0)
		abort();
#elif _WIN32
	u_long mode = blocking ? 0 : 1;

	int result = ioctlsocket(
		socket->handle,
		FIONBIO,
		&mode);

	if (result != 0)
		abort();
#endif

	socket->blocking = blocking;
}

size_t getSocketReceiveTimeout(
	const struct Socket* socket)
{
	assert(socket != NULL);

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
	uint32_t timeout;

	int size =
		sizeof(uint32_t);

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
	size_t milliseconds)
{
	assert(socket != NULL);

#if __linux__ || __APPLE__
	struct timeval timeout;
	timeout.tv_sec = milliseconds / 1000;
	timeout.tv_usec = (milliseconds % 1000) * 1000;

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
		(uint32_t)milliseconds;

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
	assert(socket != NULL);

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
	uint32_t timeout;

	int size =
		sizeof(uint32_t);

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
	size_t milliseconds)
{
	assert(socket != NULL);

#if __linux__ || __APPLE__
	struct timeval timeout;
	timeout.tv_sec = milliseconds / 1000;
	timeout.tv_usec = (milliseconds % 1000) * 1000;

	int result = setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		&timeout,
		sizeof(struct timeval));

	if (result != 0)
		abort();
#elif _WIN32
	uint32_t timeout =
		(uint32_t)milliseconds;

	int result = setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		(const char*)&timeout,
		sizeof(uint32_t));

	if (result != 0)
		abort();
#endif
}

void bindSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
{
	assert(socket != NULL);
	assert(address != NULL);

	int family = address->handle.ss_family;

#if __linux__ || __APPLE__
	socklen_t length;
#elif _WIN32
	int length;
#endif

	if (family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
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
	assert(socket != NULL);

	int result = listen(
		socket->handle,
		SOMAXCONN);

	if (result != 0)
		abort();
}

struct Socket* acceptSocket(
	struct Socket* socket)
{
	assert(socket != NULL);

	SOCKET handle = accept(
		socket->handle,
		NULL,
		0);

	if (handle == INVALID_SOCKET)
		return  NULL;

	struct Socket* _socket =
		malloc(sizeof(struct Socket));

	if(_socket == NULL)
		abort();

	_socket->handle = handle;
	return _socket;
}
bool connectSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
{
	assert(socket != NULL);
	assert(address != NULL);

	int family = address->handle.ss_family;

#if __linux__ || __APPLE__
	socklen_t length;
#elif _WIN32
	int length;
#endif

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
	enum SocketShutdown _type)
{
	assert(socket != NULL);

	int type;

	if (_type == SHUTDOWN_RECEIVE_ONLY)
		type = SHUT_RD;
	else if (_type == SHUTDOWN_SEND_ONLY)
		type = SHUT_WR;
	else if (_type == SHUTDOWN_RECEIVE_SEND)
		type = SHUT_RDWR;
	else
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
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(size > 0);
	assert(_count != NULL);

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
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(size > 0);

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
	struct SocketAddress** _address,
	size_t* _count)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(size > 0);
	assert(_address != NULL);
	assert(_count != NULL);

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
		buffer,
		size,
		0,
		(struct sockaddr*)&handle,
		&length);
#elif _WIN32
	int count = recvfrom(
		socket->handle,
		(char*)buffer,
		(int)size,
		0,
		(struct sockaddr*)&handle,
		&length);
#endif

	if (count < 0)
		return false;

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		abort();

	address->handle = handle;
	*_address = address;
	*_count = (size_t)count;
	return true;
}
bool socketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t size,
	const struct SocketAddress* address)
{
	assert(socket != NULL);
	assert(buffer != NULL);
	assert(size > 0);
	assert(address != NULL);

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
	assert(host != NULL);
	assert(service != NULL);

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));

	if (address == NULL)
		abort();

	memset(
		&address->handle,
		0,
		sizeof(struct sockaddr_storage));

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

enum AddressFamily getSocketAddressFamily(
	const struct SocketAddress* address)
{
	assert(address != NULL);

	int family = address->handle.ss_family;

	if (family == AF_INET)
		return INTERNET_PROTOCOL_V4;
	else if (family == AF_INET6)
		return INTERNET_PROTOCOL_V6;
	else
		abort();
}
void getSocketAddressIP(
	const struct SocketAddress* address,
	uint8_t ** _ip,
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
			abort();

		const struct sockaddr_in* address4 =
			(const struct sockaddr_in*)&address->handle;

		memcpy(
			ip,
			address4,
			sizeof(struct sockaddr_in));

		*_ip = ip;
		*size = sizeof(struct sockaddr_in);
	}
	else if (family == AF_INET6)
	{
		uint8_t* ip = malloc(
			sizeof(struct sockaddr_in6));

		if (ip == NULL)
			abort();

		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;

		memcpy(
			ip,
			address6,
			sizeof(struct sockaddr_in6));

		*_ip = ip;
		*size = sizeof(struct sockaddr_in6);
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
		abort();

	size_t hostLength =
		strlen(buffer);
	char* host = malloc(
		hostLength * sizeof(char));

	if (host == NULL)
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
		abort();

	size_t serviceLength =
		strlen(buffer);
	char* service = malloc(
		serviceLength * sizeof(char));

	if (service == NULL)
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
		abort();

	size_t hostLength =
		strlen(hostBuffer);
	char* host = malloc(
		hostLength * sizeof(char));

	size_t serviceLength =
		strlen(hostBuffer);
	char* service = malloc(
		serviceLength * sizeof(char));

	if (host == NULL ||
		service == NULL)
	{
		abort();
	}

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
