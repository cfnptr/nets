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

/* Create stream session function */
typedef void*(*CreateStreamSession)(
	struct StreamSession* session);

/* Destroy stream session function */
typedef void(*DestroyStreamSession)(
	void* session);

/*
 * Creates a new stream server.
 * Returns stream server on success, otherwise NULL.
 *
 * addressFamily - local stream socket address family.
 * port - pointer to the valid local address port string.
 * sessionBufferSize - socket session buffer size.
 * receiveBufferSize - socket message receive buffer size.
 * receiveTimeoutTime - socket message receive timeout time (ms).
 * receiveFunction - pointer to the valid receive function.
 * createFunction - pointer to the create function or NULL.
 * destroyFunction - pointer to the destroy function or NULL.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
struct StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* port,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	size_t receiveTimeoutTime,
	StreamSessionReceive receiveFunction,
	CreateStreamSession createFunction,
	DestroyStreamSession destroyFunction,
	void* functionArgument,
	struct SslContext* sslContext);

/*
 * Destroys specified stream server.
 * server - pointer to the stream server or NULL.
 */
void destroyStreamServer(
	struct StreamServer* server);

/*
 * Returns stream server receive buffer size.
 * server - pointer to the valid stream server.
 */
size_t getStreamServerSessionBufferSize(
	const struct StreamServer* server);

/*
 * Returns stream server receive buffer size.
 * server - pointer to the valid stream server.
 */
size_t getStreamServerReceiveBufferSize(
	const struct StreamServer* server);

/*
 * Returns stream server receive timeout time (ms).
 * server - pointer to the valid stream server.
 */
size_t getStreamServerReceiveTimeoutTime(
	const struct StreamServer* server);

/*
* Returns stream session receive function.
* server - pointer to the valid stream server.
*/
StreamSessionReceive getStreamServerReceiveFunction(
	const struct StreamServer* server);

/*
* Returns create stream session function.
* server - pointer to the valid stream server.
*/
CreateStreamSession getStreamServerCreateFunction(
	const struct StreamServer* server);

/*
* Returns destroy stream session function.
* server - pointer to the valid stream server.
*/
DestroyStreamSession getStreamServerDestroyFunction(
	const struct StreamServer* server);

/*
 * Returns stream server receive function argument.
 * server - pointer to the valid stream server.
 */
void* getStreamServerFunctionArgument(
	const struct StreamServer* server);

/*
 * Returns stream server socket.
 * server - pointer to the valid stream server.
 */
const struct Socket* getStreamServerSocket(
	const struct StreamServer* server);

/*
 * Returns stream session server.
 * session - pointer to the valid stream session.
 */
const struct StreamServer* getStreamSessionServer(
	const struct StreamSession* session);

/*
 * Returns stream session socket.
 * session - pointer to the valid stream session.
 */
const struct Socket* getStreamSessionSocket(
	const struct StreamServer* session);

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
