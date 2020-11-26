#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct Socket;
struct SocketAddress;

enum AddressFamily
{
	INTERNET_PROTOCOL_V4 = 2,
	INTERNET_PROTOCOL_V6 = 30,
};

enum SocketType
{
	STREAM_SOCKET = 1,
	DATAGRAM_SOCKET = 2,
};

enum SocketShutdown
{
	SHUTDOWN_RECEIVE_ONLY = 0,
	SHUTDOWN_SEND_ONLY = 1,
	SHUTDOWN_RECEIVE_SEND = 2,
};

struct Socket* createSocket(
	enum SocketType type,
	enum AddressFamily family);
void destroySocket(
	struct Socket* socket);

bool isSocketListening(
	const struct Socket* socket);

struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket);
struct SocketAddress* getSocketRemoteAddress(
	const struct Socket* socket);

void setSocketBlocking(
	struct Socket* socket,
	bool blocking);

size_t getSocketReceiveTimeout(
	const struct Socket* socket);
void setSocketReceiveTimeout(
	struct Socket* socket,
	size_t timeout);

size_t getSocketSendTimeout(
	const struct Socket* socket);
void setSocketSendTimeout(
	struct Socket* socket,
	size_t timeout);

void bindSocket(
	struct Socket* socket,
	const struct SocketAddress* address);
void listenSocket(
	struct Socket* socket);

bool acceptSocket(
	struct Socket* socket,
	struct Socket** acceptedSocket,
	struct SocketAddress** acceptedAddress);
bool connectSocket(
	struct Socket* socket,
	const struct SocketAddress* address);

bool shutdownSocket(
	struct Socket* socket,
	enum SocketShutdown type);

bool socketReceive(
	struct Socket* socket,
	void* buffer,
	size_t size,
	size_t* count);
bool socketSend(
	struct Socket* socket,
	const void* buffer,
	size_t size);

bool socketReceiveFrom(
	struct Socket* socket,
	void* buffer,
	size_t size,
	struct SocketAddress** address,
	size_t* count);
bool socketSendTo(
	struct Socket* socket,
	const void* buffer,
	size_t size,
	const struct SocketAddress* address);

struct SocketAddress* createSocketAddress(
	const char* host,
	const char* service);
void destroySocketAddress(
	struct SocketAddress* address);

enum AddressFamily getSocketAddressFamily(
	const struct SocketAddress* address);
void getSocketAddressIP(
	const struct SocketAddress* address,
	char** ip,
	size_t* size);
uint16_t getSocketAddressPort(
	const struct SocketAddress* address);

char* getSocketAddressHost(
	const struct SocketAddress* address);
char* getSocketAddressService(
	const struct SocketAddress* address);
void getSocketAddressHostService(
	const struct SocketAddress* address,
	char** host,
	char** service);
