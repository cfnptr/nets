#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define ANY_IP_ADDRESS_V4 "0.0.0.0"
#define ANY_IP_ADDRESS_V6 "::"

#define LOOPBACK_IP_ADDRESS_V4 "127.0.0.1"
#define LOOPBACK_IP_ADDRESS_V6 "::1"

#define ANY_IP_ADDRESS_PORT "0"

struct Socket;
struct SocketAddress;

enum AddressFamily
{
	INTERNET_PROTOCOL_V4,
	INTERNET_PROTOCOL_V6,
};

enum SocketType
{
	STREAM_SOCKET,
	DATAGRAM_SOCKET,
};

enum SocketShutdown
{
	SHUTDOWN_RECEIVE_ONLY,
	SHUTDOWN_SEND_ONLY,
	SHUTDOWN_RECEIVE_SEND,
};

struct Socket* createSocket(
	enum SocketType type,
	enum AddressFamily family);
void destroySocket(
	struct Socket* socket);

enum SocketType getSocketType(
	const struct Socket* socket);
bool isSocketListening(
	const struct Socket* socket);

struct SocketAddress* getSocketLocalAddress(
	const struct Socket* socket);
struct SocketAddress* getSocketRemoteAddress(
	const struct Socket* socket);

bool getSocketBlocking(
	const struct Socket* socket);
void setSocketBlocking(
	struct Socket* socket,
	bool blocking);

size_t getSocketReceiveTimeout(
	const struct Socket* socket);
void setSocketReceiveTimeout(
	struct Socket* socket,
	size_t milliseconds);

size_t getSocketSendTimeout(
	const struct Socket* socket);
void setSocketSendTimeout(
	struct Socket* socket,
	size_t milliseconds);

void bindSocket(
	struct Socket* socket,
	const struct SocketAddress* address);
void listenSocket(
	struct Socket* socket);

struct Socket* acceptSocket(
	struct Socket* socket);
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
	uint8_t** ip,
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
