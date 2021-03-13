#pragma once
#include "mpnw/socket.h"

/* Stream server instance handle (TCP) */
struct StreamServer;
/* Stream server session instance handle (TCP) */
struct StreamSession;

/* Stream session message receive function */
typedef bool(*StreamSessionReceive)(
	struct StreamServer* streamServer,
	struct StreamSession* streamSession,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/* Stream session create function */
typedef bool(*StreamSessionCreate)(
	struct StreamServer* streamServer,
	struct Socket* streamSocket,
	void** sessionHandle);

/* Stream session destroy function */
typedef void(*StreamSessionDestroy)(
	struct StreamServer* streamServer,
	struct StreamSession* streamSession);

/*
 * Creates a new stream server (TCP).
 * Returns stream server on success, otherwise NULL.
 *
 * addressFamily - local stream socket address family.
 * port - pointer to the valid local address port string.
 * sessionBufferSize - socket session buffer size.
 * receiveBufferSize - socket message receive buffer size.
 * receiveTimeoutTime - socket message receive timeout time (s).
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
	double receiveTimeoutTime,
	StreamSessionReceive receiveFunction,
	StreamSessionCreate createFunction,
	StreamSessionDestroy destroyFunction,
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
 * Returns stream server receive function.
 * server - pointer to the valid stream server.
 */
StreamSessionReceive getStreamServerReceiveFunction(
	const struct StreamServer* server);

/*
 * Returns stream server create function.
 * server - pointer to the valid stream server.
 */
StreamSessionCreate getStreamServerCreateFunction(
	const struct StreamServer* server);

/*
 * Returns stream server destroy function.
 * server - pointer to the valid stream server.
 */
StreamSessionDestroy getStreamServerDestroyFunction(
	const struct StreamServer* server);

/*
 * Returns stream server receive timeout time (s).
 * server - pointer to the valid stream server.
 */
double getStreamServerReceiveTimeoutTime(
	const struct StreamServer* server);

/*
 * Returns stream server handle.
 * server - pointer to the valid stream server.
 */
void* getStreamServerHandle(
	const struct StreamServer* server);

/*
 * Returns stream server socket.
 * server - pointer to the valid stream server.
 */
struct Socket* getStreamServerSocket(
	const struct StreamServer* server);

/*
 * Returns stream server session socket.
 * session - pointer to the valid stream server session.
 */
struct Socket* getStreamSessionSocket(
	const struct StreamSession* session);

/*
 * Returns stream server session handle.
 * session - pointer to the valid stream server session.
 */
void* getStreamSessionHandle(
	const struct StreamSession* session);

/*
 * Sends datagram to the specified session.
 * Returns true on success.
 *
 * session - pointer to the valid stream session.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool streamSessionSend(
	struct StreamSession* streamSession,
	const void* buffer,
	size_t count);
