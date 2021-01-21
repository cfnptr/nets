#pragma once
#include "mpnw/socket.h"

/* HTTP server instance handle */
struct HttpServer;

/* HTTP session request receive function */
typedef const char*(*HttpSessionReceive)(
	const char* buffer,
	size_t count,
	void* argument);

struct HttpServer* createHttpServer(
	uint8_t addressFamily,
	struct SslContext* sslContext,
	const char* port,
	size_t sessionBufferSize,
	StreamSessionReceive receiveFunction,
	size_t receiveTimeoutTime,
	void* functionArgument,
	size_t receiveBufferSize);
void destroyHttpServer();
