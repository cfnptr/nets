#pragma once
#include "mpnw/socket.h"

struct StreamServer;

typedef bool(*StreamServerAccept)(
	struct Socket*,
	const struct SocketAddress*);
typedef bool(*StreamSessionReceive)(
	size_t count,
	struct Socket* socket,
	const char* receiveBuffer);

struct StreamServer* createStreamServer(
	const struct SocketAddress* address,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	uint32_t messageTimeoutTime,
	StreamServerAccept serverAccept,
	StreamSessionReceive sessionReceive);
void destroyStreamServer(
	struct StreamServer* server);

bool isStreamServerRunning(
	const struct StreamServer* server);

