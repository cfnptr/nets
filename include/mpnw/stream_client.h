#pragma once
#include "mpnw/socket.h"

struct StreamClient;

typedef bool(*StreamClientReceive)(
	size_t count,
	struct Socket* socket,
	const char* receiveBuffer);

struct StreamClient* createStreamClient(
	struct SocketAddress* address,
	size_t receiveBufferSize,
	uint32_t messageTimeoutTime,
	StreamClientReceive clientReceive);
void destroyStreamClient(
	struct StreamClient* client);

bool getStreamClientRunning(
	const struct StreamClient* server,
	bool* running);
