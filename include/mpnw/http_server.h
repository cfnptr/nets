#pragma once
#include "mpnw/http.h"
#include "mpnw/stream_server.h"

/* HTTP server instance handle */
struct HttpServer;

/* HTTP session request receive function */
typedef const char*(*HttpSessionReceive)(
	struct StreamSession* session,
	const struct HttpRequest* request,
	void* argument);

/*
 * Creates a new HTTP server.
 * Returns HTTP server on success, otherwise null.
 *
 * addressFamily - local HTTP socket address family.
 * port - pointer to the valid local address port string.
 * sessionBufferSize - socket session buffer size.
 * receiveFunction - pointer to the valid receive function.
 * receiveTimeoutTime - socket message receive timeout time.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket message receive buffer size.
 * sslContext - pointer to the SSL context or NULL.
 */
struct HttpServer* createHttpServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	HttpSessionReceive receiveFunction,
	size_t receiveTimeoutTime,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext);

/*
 * Destroys specified stream server.
 * server - pointer to the HTTP server or NULL.
 */
void destroyHttpServer(
	struct HttpServer* server);

/*
 * Returns HTTP server stream.
 * client - pointer to the valid HTTP server.
 */
const struct StreamServer* getHttpClientStream(
	const struct HttpServer* server);

/*
 * Sends response to the HTTP session.
 * Returns true on success.
 *
 * session - pointer to the valid stream session.
 * version - HTTP protocol version.
 * status - HTTP response status code.
 */
bool httpSessionSend(
	struct StreamSession* session,
	uint8_t version,
	uint16_t status);

