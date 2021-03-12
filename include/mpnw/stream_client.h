#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle (TCP) */
struct StreamClient;

/* Stream client message receive function */
typedef bool(*StreamClientReceive)(
	struct StreamClient* streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Creates a new stream client (TCP).
 * Returns stream client on success, otherwise NULL.
 *
 * addressFamily - local stream socket address family.
 * receiveBufferSize - socket message receive buffer size.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
struct StreamClient* createStreamClient(
	uint8_t addressFamily,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	void* functionArgument,
	struct SslContext* sslContext);

/*
 * Destroys specified stream client.
 * client - pointer to the stream client or NULL.
 */
void destroyStreamClient(
	struct StreamClient* client);

/*
* Returns stream client receive buffer size.
* client - pointer to the valid stream client.
*/
size_t getStreamClientReceiveBufferSize(
	const struct StreamClient* client);

/*
 * Returns stream client receive function argument.
 * client - pointer to the valid stream client.
 */
void* getStreamClientFunctionArgument(
	const struct StreamClient* client);

/*
 * Returns stream client socket.
 * client - pointer to the valid stream client.
 */
struct Socket* getStreamClientSocket(
	const struct StreamClient* client);

/*
 * Returns current stream client running state
 * client - pointer to the valid stream client.
 */
bool isStreamClientRunning(
	const struct StreamClient* client);

/*
 * Connects stream client to the server.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid address.
 * timeoutTime - attempt time out time (ms).
 */
bool connectStreamClient(
	struct StreamClient* streamClient,
	const struct SocketAddress* address,
	double timeoutTime);

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
