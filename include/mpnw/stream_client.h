#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle */
struct StreamClient;

/* Stream client message receive function */
typedef void(*StreamClientReceive)(
	struct StreamClient* client,
	const uint8_t* buffer,
	size_t count,
	void* argument);

/*
 * Creates a new stream client.
 * Returns stream client on success, otherwise null.
 *
 * localAddress - pointer to the valid client address.
 * remoteAddress - pointer to the valid server address.
 * receiveFunctions - pointer to the valid receive functions.
 * receiveFunctionCount - receive function array item count.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket message receive buffer size.
 */
struct StreamClient* createStreamClient(
	const struct SocketAddress* localAddress,
	const struct SocketAddress* remoteAddress,
	StreamClientReceive* receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize);

/*
 * Destroys specified stream client.
 * client - pointer to the valid stream client.
 */
void destroyStreamClient(
	struct StreamClient* client);

/*
 * Returns true if stream client is still running;
 * client - pointer to the valid stream client.
 */
bool isStreamClientRunning(
	const struct StreamClient* client);

/*
 * Sends message to the server.
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
