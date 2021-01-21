#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle */
struct StreamClient;

/* Stream client message receive function */
typedef bool(*StreamClientReceive)(
	struct StreamClient* client,
	const uint8_t* buffer,
	size_t count,
	void* argument);

/*
 * Creates a new stream client.
 * Returns stream client on success, otherwise null.
 *
 * addressFamily - local stream socket address family.
 * sslContext - pointer to the SSL context or NULL.
 * remoteAddress - pointer to the valid server address.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket message receive buffer size.
 */
struct StreamClient* createStreamClient(
	uint8_t addressFamily,
	struct SslContext* sslContext,
	const struct SocketAddress* remoteAddress,
	StreamClientReceive receiveFunction,
	void* functionArgument,
	size_t receiveBufferSize);

/*
 * Destroys specified stream client.
 * client - pointer to the stream client or NULL.
 */
void destroyStreamClient(
	struct StreamClient* client);

/*
 * Returns current stream client running state
 * client - pointer to the valid stream client.
 */
bool getStreamClientRunning(
	const struct StreamClient* client);

/*
 * Sends message to the stream server.
 * Returns true on success.
 *
 * client - pointer to the valid stream client.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool streamClientSend(
	struct StreamClient* client,
	const void* buffer,
	size_t count);
