#pragma once
#include "mpnw/socket.h"

struct StreamServer;

typedef bool(*SessionAcceptHandler)(
	struct Socket*,
	const struct SocketAddress*);
typedef bool(*SessionReceiveHandler)(
	size_t count,
	struct Socket* socket,
	const char* receiveBuffer);

struct StreamServer* mpnwCreateStreamServer(
	const struct SocketAddress* address,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	uint32_t sessionTimeoutTime,
	SessionAcceptHandler acceptHandler,
	SessionReceiveHandler receiveHandler);
void mpnwDestroyStreamServer(
	struct StreamServer* server);

bool mpnwGetStreamServerRunning(
	const struct StreamServer* server,
	bool* running);

