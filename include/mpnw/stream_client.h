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
 * remoteAddress - pointer to the valid server address.
 * receiveFunctions - pointer to the valid receive functions.
 * receiveFunctionCount - receive function array item count.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket message receive buffer size.
 */
struct StreamClient* createStreamClient(
	enum AddressFamily addressFamily,
	const struct SocketAddress* remoteAddress,
	const StreamClientReceive* receiveFunctions,
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
 * Gets current stream client running state
 * Returns true on successful get.
 *
 * client - pointer to the valid stream client.
 * running - pointer to the valid running value.
 */
bool getStreamClientRunning(
	const struct StreamClient* client,
	bool* running);

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
