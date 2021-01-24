#pragma once
#include "mpnw/socket.h"

/* Stream server instance handle */
struct StreamServer;
/* Stream session instance handle */
struct StreamSession;

/* Stream session message receive function */
typedef bool(*StreamSessionReceive)(
	struct StreamSession* session,
	const uint8_t* buffer,
	size_t count,
	void* argument);

/* Stream session receive timeout function */
typedef void(*StreamSessionTimeout)(
	struct StreamSession* session,
	void* argument);

/*
 * Creates a new stream server.
 * Returns stream server on success, otherwise NULL.
 *
 * addressFamily - local stream socket address family.
 * port - pointer to the valid local address port string.
 * sessionBufferSize - socket session buffer size.
 * receiveFunction - pointer to the valid receive function.
 * timeoutFunction - pointer to the valid timeout function.
 * receiveTimeoutTime - socket message receive timeout time.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket message receive buffer size.
 * sslContext - pointer to the SSL context or NULL.
 */
struct StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	StreamSessionReceive receiveFunction,
	StreamSessionTimeout timeoutFunction,
	size_t receiveTimeoutTime,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext);

/*
 * Destroys specified stream server.
 * server - pointer to the stream server or NULL.
 */
void destroyStreamServer(
	struct StreamServer* server);

/*
 * Returns stream server socket.
 * client - pointer to the valid stream server.
 */
const struct Socket* getStreamServerSocket(
	const struct StreamServer* server);

/*
 * Sends datagram to the specified session.
 * Returns true on success.
 *
 * session - pointer to the valid stream session.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool streamSessionSend(
	struct StreamSession* session,
	const void* buffer,
	size_t count);
