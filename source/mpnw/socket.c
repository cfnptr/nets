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
// TODO:
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

struct Socket* mpnwCreateSocket(
	enum SocketType type,
	enum AddressFamily family)
{
	SOCKET handle = socket(
		family,
		type,
		0);

	if(handle == INVALID_SOCKET)
		return NULL;

	struct Socket* socket =
		malloc(sizeof(struct Socket));
	socket->handle = handle;
	return socket;
}
void mpnwDestroySocket(
	struct Socket* socket)
{
	if(socket)
	{
		mpnwShutdownSocket(
			socket,
			SHUTDOWN_RECEIVE_SEND);

#if __linux__ || __APPLE__
		close(socket->handle);
#elif _WIN32
		closesocket(socket->handle);
#endif
	}

	free(socket);
}

bool mpnwGetSocketListening(
	const struct Socket* socket,
	bool* _listening)
{
	if(!socket || !_listening)
		return false;

	socklen_t length =
		sizeof(bool);

	bool listening;

	int result = getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_ACCEPTCONN,
		(char*)&listening,
		&length);

	if(result != 0)
		return false;

	*_listening = listening;
	return true;
}
struct SocketAddress* mpnwGetSocketLocalAddress(
	const struct Socket* socket)
{
	if(!socket)
		return NULL;

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

	if(result != 0)
		return NULL;

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));
	address->handle = handle;
	return address;
}
struct SocketAddress* mpnwGetSocketRemoteAddress(
	const struct Socket* socket)
{
	if(!socket)
		return NULL;

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

	if(result != 0)
		return NULL;

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));
	address->handle = handle;
	return address;
}

bool mpnwSetSocketBlocking(
	struct Socket* socket,
	bool blocking)
{
	if(!socket)
		return false;

#if __linux__ || __APPLE__
	int flags = fcntl(
		socket->handle,
		F_GETFL,
		0);

	if (flags == -1)
		return false;

	flags = blocking ?
		(flags & ~O_NONBLOCK) :
		(flags | O_NONBLOCK);

	return fcntl(
		socket->handle,
		F_SETFL,
		flags) != -1;
#elif _WIN32
	u_long mode = blocking ? 0 : 1;

	return ioctlsocket(
		socket->handle,
		FIONBIO,
		&mode) == 0;
#endif
}

bool mpnwGetSocketReceiveTimeout(
	const struct Socket* socket,
	uint32_t* _timeout)
{
	if(!socket || !_timeout)
		return false;

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

	if(result != 0)
		return false;

	*_timeout =
		timeout.tv_sec * 1000 +
		timeout.tv_usec / 1000;
	return true;
#elif _WIN32
	int size =
		sizeof(uint32_t);

	return getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		(char*)&timeout,
		&size) == 0;
#endif
}
bool mpnwSetSocketReceiveTimeout(
	struct Socket* socket,
	uint32_t _timeout)
{
	if(!socket)
		return false;

#if __linux__ || __APPLE__
	struct timeval timeout;
	timeout.tv_sec = _timeout / 1000;
	timeout.tv_usec = (_timeout % 1000) * 1000;

	return setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		&timeout,
		sizeof(struct timeval)) == 0;
#elif _WIN32
	return setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_RCVTIMEO,
		(const char*)&_timeout,
		sizeof(uint32_t)) == 0;
#endif
}

bool mpnwGetSocketSendTimeout(
	const struct Socket* socket,
	uint32_t* _timeout)
{
	if(!socket || !_timeout)
		return false;

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

	if(result != 0)
		return false;

	*_timeout =
		timeout.tv_sec * 1000 +
		timeout.tv_usec / 1000;
	return true;
#elif _WIN32
	int size =
		sizeof(uint32_t);

	return getsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		(char*)&timeout,
		&size) == 0;
#endif
}
bool mpnwSetSocketSendTimeout(
	struct Socket* socket,
	uint32_t _timeout)
{
	if(!socket)
		return false;

#if __linux__ || __APPLE__
	struct timeval timeout;
	timeout.tv_sec = _timeout / 1000;
	timeout.tv_usec = (_timeout % 1000) * 1000;

	return setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		&timeout,
		sizeof(struct timeval)) == 0;
#elif _WIN32
	return setsockopt(
		socket->handle,
		SOL_SOCKET,
		SO_SNDTIMEO,
		(const char*)&_timeout,
		sizeof(uint32_t)) == 0;
#endif
}

bool mpnwBindSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
{
	if(!socket || !address)
		return false;

	int family = address->handle.ss_family;

	socklen_t length;

	if(family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if(family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		return false;

	return bind(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length) == 0;
}
bool mpnwListenSocket(
	struct Socket* socket)
{
	if(!socket)
		return false;

	return listen(
		socket->handle,
		SOMAXCONN) == 0;
}

bool mpnwAcceptSocket(
	struct Socket* socket,
	struct Socket** _acceptedSocket,
	struct SocketAddress** _acceptedAddress)
{
	if(!socket ||
		!_acceptedSocket ||
		!_acceptedAddress)
	{
		return false;
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

	if (socketHandle == INVALID_SOCKET)
		return false;

	struct Socket* acceptSocket =
		malloc(sizeof(struct Socket));
	acceptSocket->handle = socketHandle;
	*_acceptedSocket = acceptSocket;

	struct SocketAddress* acceptAddress =
		malloc(sizeof(struct SocketAddress));
	acceptAddress->handle = addressHandle;
	*_acceptedAddress = acceptAddress;
	return true;
}
bool mpnwConnectSocket(
	struct Socket* socket,
	const struct SocketAddress* address)
{
	if(!socket || !address)
		return false;

	int family = address->handle.ss_family;

	socklen_t length;

	if(family == AF_INET)
		length = sizeof(struct sockaddr_in);
	else if(family == AF_INET6)
		length = sizeof(struct sockaddr_in6);
	else
		return false;

	return connect(
		socket->handle,
		(const struct sockaddr*)&address->handle,
		length) == 0;
}

bool mpnwShutdownSocket(
	struct Socket* socket,
	enum SocketShutdown type)
{
	if(!socket)
		return false;

	return shutdown(
		socket->handle,
		type) == 0;
}

bool mpnwSocketReceive(
	struct Socket* socket,
	void* buffer,
	size_t size,
	size_t* _count)
{
	if(!socket || !buffer || !_count || !size)
		return false;

	int count = recv(
		socket->handle,
		(char*)buffer,
		size,
		0);

	if(count < 0)
		return false;

	*_count = (size_t)count;
	return true;
}
bool mpnwSocketSend(
	struct Socket* socket,
	const void* buffer,
	size_t size)
{
	if(!socket || !buffer || !size)
		return false;

	return send(
		socket->handle,
		(const char*)buffer,
		size,
		0) == size;
}

bool mpnwSocketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress** address,
	size_t* _count)
{
	if(!socket || !buffer || !address || !_count)
		return false;

	socklen_t length =
		sizeof(struct sockaddr_storage);

	struct sockaddr_storage handle;

	memset(
		&handle,
		0,
		sizeof(struct sockaddr_storage));

	int count = recvfrom(
		socket->handle,
		(char*)buffer,
		size,
		0,
		(struct sockaddr*)&handle,
		&length);

	if(count < 0)
		return false;

	struct SocketAddress* newAddress =
		malloc(sizeof(struct SocketAddress));
	newAddress->handle = handle;
	*address = newAddress;
	*_count = (size_t)count;
	return true;
}
bool mpnwSocketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t size,
	const struct SocketAddress* address)
{
	if(!socket || !buffer || !address)
		return false;

	return sendto(
		socket->handle,
		(const char*)buffer,
		size,
		0,
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage)) == size;
}

struct SocketAddress* mpnwCreateSocketAddress(
	const char* host,
	const char* service)
{
	if(!host || !service)
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
		freeaddrinfo(addressInfos);
		return NULL;
	}

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

	struct SocketAddress* address =
		malloc(sizeof(struct SocketAddress));
	address->handle = handle;
	return address;
}
void mpnwDestroySocketAddress(
	struct SocketAddress* address)
{
	free(address);
}

bool mpnwGetSocketAddressFamily(
	const struct SocketAddress* address,
	enum AddressFamily* _family)
{
	if(!address || !_family)
		return false;

	int family = address->handle.ss_family;

	if(family != AF_INET && family != AF_INET6)
		return false;

	*_family = family;
	return true;
}
bool mpnwGetSocketAddressIP(
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

		memcpy(
			ip,
			address4,
			sizeof(const struct sockaddr_in));

		*_ip = ip;
		*size = sizeof(const struct sockaddr_in6);
		return true;
	}
	else if (family == AF_INET6)
	{
		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;

		char* ip = malloc(
			sizeof(const struct sockaddr_in6));

		memcpy(
			ip,
			address6,
			sizeof(const struct sockaddr_in6));

		*_ip = ip;
		*size = sizeof(const struct sockaddr_in6);
		return true;
	}
	else
	{
		return false;
	}
}
bool mpnwGetSocketAddressPort(
	const struct SocketAddress* address,
	uint16_t* port)
{
	if(!address || !port)
		return false;

	int family = address->handle.ss_family;

	if (family == AF_INET)
	{
		const struct sockaddr_in* address4 =
			(const struct sockaddr_in*)&address->handle;
		*port = (uint16_t)address4->sin_port;
		return true;
	}
	else if (family == AF_INET6)
	{
		const struct sockaddr_in6* address6 =
			(const struct sockaddr_in6*)&address->handle;
		*port = (uint16_t)address6->sin6_port;
		return true;
	}
	else
	{
		return false;
	}
}

bool mpnwGetSocketAddressHost(
	const struct SocketAddress* address,
	char** _host)
{
	if(!address || !_host)
		return false;

	char* host = calloc(
		NI_MAXHOST,
		sizeof(char));

	int flags =
		NI_NUMERICHOST;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		host,
		NI_MAXHOST,
		NULL,
		0,
		flags);

	if (result != 0)
		return false;

	*_host = host;
	return true;
}
bool mpnwGetSocketAddressService(
	const struct SocketAddress* address,
	char** _service)
{
	if(!address || !_service)
		return false;

	char* service = calloc(
		NI_MAXSERV,
		sizeof(char));

	int flags =
		NI_NUMERICSERV;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		NULL,
		0,
		service,
		NI_MAXSERV,
		flags);

	if (result != 0)
		return false;

	*_service = service;
	return true;
}
bool mpnwGetSocketAddressHostService(
	const struct SocketAddress* address,
	char** _host,
	char** _service)
{
	if(!address || !_host || !_service)
		return false;

	char* host = calloc(
		NI_MAXHOST,
		sizeof(char));
	char* service = calloc(
		NI_MAXSERV,
		sizeof(char));

	int flags =
		NI_NUMERICHOST |
		NI_NUMERICSERV;

	int result = getnameinfo(
		(const struct sockaddr*)&address->handle,
		sizeof(struct sockaddr_storage),
		host,
		NI_MAXHOST,
		service,
		NI_MAXSERV,
		flags);

	if (result != 0)
		return false;

	*_host = host;
	*_service = service;
	return true;
}
