#pragma once
#include <stdlib.h>
#include <stdbool.h>

struct Socket;
struct SocketAddress;

enum AddressFamily : int
{
	INTERNET_PROTOCOL_V4 = 2,
	INTERNET_PROTOCOL_V6 = 30,
};

enum SocketType : int
{
	STREAM_SOCKET = 1,
	DATAGRAM_SOCKET = 2,
};

enum SocketShutdown : int
{
	SHUTDOWN_RECEIVE_ONLY = 0,
	SHUTDOWN_SEND_ONLY = 1,
	SHUTDOWN_RECEIVE_SEND = 2,
};

struct Socket* mpnwCreateSocket(
	enum SocketType type,
	enum AddressFamily family);
void mpnwDestroySocket(
	struct Socket* socket);

bool mpnwGetSocketListening(
	const struct Socket* socket,
	bool* listening);
struct SocketAddress* mpnwGetSocketLocalAddress(
	const struct Socket* socket);
struct SocketAddress* mpnwGetSocketRemoteAddress(
	const struct Socket* socket);

bool mpnwSetSocketBlocking(
	struct Socket* socket,
	bool blocking);

bool mpnwGetSocketReceiveTimeout(
	const struct Socket* socket,
	uint32_t* timeout);
bool mpnwSetSocketReceiveTimeout(
	struct Socket* socket,
	uint32_t timeout);

bool mpnwGetSocketSendTimeout(
	const struct Socket* socket,
	uint32_t* timeout);
bool mpnwSetSocketSendTimeout(
	struct Socket* socket,
	uint32_t timeout);

bool mpnwBindSocket(
	struct Socket* socket,
	const struct SocketAddress* address);
bool mpnwListenSocket(
	struct Socket* socket);

bool mpnwAcceptSocket(
	struct Socket* socket,
	struct Socket** acceptedSocket,
	struct SocketAddress** acceptedAddress);
bool mpnwConnectSocket(
	struct Socket* socket,
	const struct SocketAddress* address);

bool mpnwShutdownSocket(
	struct Socket* socket,
	enum SocketShutdown type);

bool mpnwSocketReceive(
	struct Socket* socket,
	void* buffer,
	size_t size,
	size_t* count);
bool mpnwSocketSend(
	struct Socket* socket,
	const void* buffer,
	size_t size);

bool mpnwSocketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress** address,
	size_t* count);
bool mpnwSocketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t size,
	const struct SocketAddress* address);

struct SocketAddress* mpnwCreateSocketAddress(
	const char* host,
	const char* service);
void mpnwDestroySocketAddress(
	struct SocketAddress* address);

bool mpnwGetSocketAddressFamily(
	const struct SocketAddress* address,
	enum AddressFamily* family);
bool mpnwGetSocketAddressIP(
	const struct SocketAddress* address,
	char** ip,
	size_t* size);
bool mpnwGetSocketAddressPort(
	const struct SocketAddress* address,
	uint16_t* port);

bool mpnwGetSocketAddressHost(
	const struct SocketAddress* address,
	char** host);
bool mpnwGetSocketAddressService(
	const struct SocketAddress* address,
	char** service);
bool mpnwGetSocketAddressHostService(
	const struct SocketAddress* address,
	char** host,
	char** service);
