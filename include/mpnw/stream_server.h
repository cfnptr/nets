#pragma once
#include "mpnw/socket.h"

/* Stream server instance handle (TCP) */
typedef struct StreamServer StreamServer;
/* Stream server session instance handle (TCP) */
typedef struct StreamSession StreamSession;

/*
 * Stream session create function.
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionCreate)(
	StreamServer* server,
	Socket* socket,
	void** handle);

/* Stream session destroy function */
typedef void(*OnStreamSessionDestroy)(
	StreamServer* server,
	StreamSession* session);

/*
 * Stream session update function.
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionUpdate)(
	StreamServer* server,
	StreamSession* session);

/*
 * Stream session message receive function
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionReceive)(
	StreamServer* server,
	StreamSession* session,
	const uint8_t* buffer,
	size_t byteCount);

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
 * handle - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
StreamServer* createStreamServer(
	uint8_t addressFamily,
	const char* service,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	OnStreamSessionCreate onCreate,
	OnStreamSessionDestroy onDestroy,
	OnStreamSessionUpdate onUpdate,
	OnStreamSessionReceive onReceive,
	void* handle,
	SslContext* sslContext);

/*
 * Destroys specified stream server.
 * server - pointer to the stream server or NULL.
 */
void destroyStreamServer(StreamServer* server);

/*
 * Returns stream server session buffer size.
 * server - pointer to the valid stream server.
 */
size_t getStreamServerSessionBufferSize(
	const StreamServer* server);

/*
 * Returns stream server receive buffer size.
 * server - pointer to the valid stream server.
 */
size_t getStreamServerReceiveBufferSize(
	const StreamServer* server);

/*
 * Returns stream server create function.
 * server - pointer to the valid stream server.
 */
OnStreamSessionCreate getStreamServerOnCreate(
	const StreamServer* server);

/*
 * Returns stream server destroy function.
 * server - pointer to the valid stream server.
 */
OnStreamSessionDestroy getStreamServerOnDestroy(
	const StreamServer* server);

/*
 * Returns stream server update function.
 * server - pointer to the valid stream server.
 */
OnStreamSessionUpdate getStreamServerOnUpdate(
	const StreamServer* server);

/*
 * Returns stream server receive function.
 * server - pointer to the valid stream server.
 */
OnStreamSessionReceive getStreamServerOnReceive(
	const StreamServer* server);

/*
 * Returns stream server handle.
 * server - pointer to the valid stream server.
 */
void* getStreamServerHandle(
	const StreamServer* server);

/*
 * Returns stream server socket.
 * server - pointer to the valid stream server.
 */
Socket* getStreamServerSocket(
	const StreamServer* server);

/*
 * Returns stream server session socket.
 * session - pointer to the valid stream server session.
 */
Socket* getStreamSessionSocket(
	const StreamSession* session);

/*
 * Returns stream server session handle.
 * session - pointer to the valid stream server session.
 */
void* getStreamSessionHandle(
	const StreamSession* session);

/*
 * Receive buffered datagrams.
 * Returns true if update actions occurred.
 *
 * server - pointer to the valid stream server.
 */
bool updateStreamServer(StreamServer* server);

/*
 * Sends datagram to the specified session.
 * Returns true on success.
 *
 * session - pointer to the valid stream session.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool streamSessionSend(
	StreamSession* session,
	const void* buffer,
	size_t count);
