#pragma once
#include "mpnw/socket.h"

struct StreamClient;

typedef bool(*StreamClientReceive)(
	size_t count,
	struct Socket* socket,
	const uint8_t* receiveBuffer,
	void* receiveArgument);

struct StreamClient* createStreamClient(
	const struct SocketAddress* address,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	void* receiveArgument);
void destroyStreamClient(
	struct StreamClient* client);

bool isStreamClientRunning(
	const struct StreamClient* server);
