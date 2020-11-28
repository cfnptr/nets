#pragma once
#include "mpnw/socket.h"

struct StreamServer;

typedef bool(*StreamServerAccept)(
	struct Socket*,
	const struct SocketAddress*,
	void* argument);
typedef bool(*StreamSessionReceive)(
	size_t count,
	struct Socket* socket,
	const uint8_t* receiveBuffer,
	void* argument);

struct StreamServer* createStreamServer(
	const struct SocketAddress* address,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	StreamServerAccept acceptFunction,
	StreamSessionReceive receiveFunction,
	void* acceptArgument,
	void* receiveArgument);
void destroyStreamServer(
	struct StreamServer* server);

bool isStreamServerRunning(
	const struct StreamServer* server);

