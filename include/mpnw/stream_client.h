#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle (TCP) */
typedef struct StreamClient StreamClient;

/* Stream client message receive function */
typedef bool(*StreamClientReceive)(
	StreamClient* streamClient,
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
StreamClient* createStreamClient(
	uint8_t addressFamily,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	void* handle,
	SslContext* sslContext);

/*
 * Destroys specified stream client.
 * client - pointer to the stream client or NULL.
 */
void destroyStreamClient(StreamClient* client);

/*
* Returns stream client receive buffer size.
* client - pointer to the valid stream client.
*/
size_t getStreamClientReceiveBufferSize(
	const StreamClient* client);

/*
* Returns stream client receive function.
* client - pointer to the valid stream client.
*/
StreamClientReceive getStreamClientReceiveFunction(
	const StreamClient* client);

/*
 * Returns stream client handle.
 * client - pointer to the valid stream client.
 */
void* getStreamClientHandle(
	const StreamClient* client);

/*
 * Returns stream client socket.
 * client - pointer to the valid stream client.
 */
Socket* getStreamClientSocket(
	const StreamClient* client);

/*
 * Returns current stream client running state
 * client - pointer to the valid stream client.
 */
bool isStreamClientRunning(
	const StreamClient* client);

/*
 * Connects stream client to the server.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid address.
 * timeoutTime - attempt time out time (ms).
 */
bool connectStreamClient(
	StreamClient* streamClient,
	const SocketAddress* address,
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
	StreamClient* client,
	const void* buffer,
	size_t count);
