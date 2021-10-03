#pragma once
#include "mpnw/socket.h"

/* Stream server instance handle (TCP) */
typedef struct StreamServer* StreamServer;
/* Stream server session instance handle (TCP) */
typedef struct StreamSession* StreamSession;

/*
 * Stream session create function.
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionCreate)(
	StreamServer server,
	Socket socket,
	void** handle);

/* Stream session destroy function */
typedef void(*OnStreamSessionDestroy)(
	StreamServer server,
	StreamSession session);

/*
 * Stream session update function.
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionUpdate)(
	StreamServer server,
	StreamSession session);

/*
 * Stream session receive function
 * Destroys session on false return result.
 */
typedef bool(*OnStreamSessionReceive)(
	StreamServer server,
	StreamSession session,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Create a new stream server instance (TCP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * service - local address service string.
 * sessionBufferSize - socket session buffer size.
 * receiveBufferSize - socket message receive buffer size.
 * receiveTimeoutTime - socket message receive timeout time (s).
 * receiveFunction - message receive function.
 * createFunction - create function or NULL.
 * destroyFunction - destroy function or NULL.
 * handle - receive function argument.
 * sslContext - SSL context or NULL.
 */
MpnwResult createStreamServer(
	AddressFamily addressFamily,
	const char* service,
	size_t sessionBufferSize,
	size_t receiveBufferSize,
	OnStreamSessionCreate onCreate,
	OnStreamSessionDestroy onDestroy,
	OnStreamSessionUpdate onUpdate,
	OnStreamSessionReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamServer* streamServer);

/*
 * Destroy stream server instance.
 * server - stream server instance or NULL.
 */
void destroyStreamServer(StreamServer server);

/*
 * Returns stream server session buffer size.
 * server - stream server instance.
 */
size_t getStreamServerSessionBufferSize(StreamServer server);

/*
 * Returns stream server receive buffer size.
 * server - stream server instance.
 */
size_t getStreamServerReceiveBufferSize(StreamServer server);

/*
 * Returns stream server create function.
 * server - stream server instance.
 */
OnStreamSessionCreate getStreamServerOnCreate(StreamServer server);

/*
 * Returns stream server destroy function.
 * server - stream server instance.
 */
OnStreamSessionDestroy getStreamServerOnDestroy(StreamServer server);

/*
 * Returns stream server update function.
 * server - stream server instance.
 */
OnStreamSessionUpdate getStreamServerOnUpdate(StreamServer server);

/*
 * Returns stream server receive function.
 * server - stream server instance.
 */
OnStreamSessionReceive getStreamServerOnReceive(StreamServer server);

/*
 * Returns stream server handle.
 * server - stream server instance.
 */
void* getStreamServerHandle(StreamServer server);

/*
 * Returns stream server socket.
 * server - stream server instance.
 */
Socket getStreamServerSocket(StreamServer server);

/*
 * Returns stream session socket.
 * session - stream session instance.
 */
Socket getStreamSessionSocket(StreamSession session);

/*
 * Returns stream session handle.
 * session - stream session instance.
 */
void* getStreamSessionHandle(StreamSession session);

/*
 * Receive buffered datagrams.
 * Returns true if update actions occurred.
 *
 * server - stream server instance.
 */
bool updateStreamServer(StreamServer server);

/*
 * Send datagram to the specified session.
 * Returns true on success.
 *
 * session - stream session instance.
 * buffer - message send buffer.
 * count - send byte count.
 */
bool streamSessionSend(
	StreamSession session,
	const void* buffer,
	size_t count);
