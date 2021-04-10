#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle (TCP) */
typedef struct StreamClient StreamClient;

/* Stream client message receive function */
typedef void(*OnStreamClientReceive)(
	StreamClient* client,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Creates a new stream client (TCP).
 * Returns stream client on success, otherwise NULL.
 *
 * addressFamily - local stream socket address family.
 * bufferSize - socket message receive buffer size.
 * onReceive - pointer to the valid receive function.
 * handle - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
StreamClient* createStreamClient(
	uint8_t addressFamily,
	size_t bufferSize,
	OnStreamClientReceive onReceive,
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
size_t getStreamClientBufferSize(
	const StreamClient* client);

/*
* Returns stream client receive function.
* client - pointer to the valid stream client.
*/
OnStreamClientReceive getStreamClientOnReceive(
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
 * Connects stream client to the server.
 * Returns true on success.
 *
 * socket - pointer to the valid socket.
 * address - pointer to the valid address.
 * timeoutTime - attempt time out time (ms).
 */
bool connectStreamClient(
	StreamClient* client,
	const SocketAddress* address,
	double timeout);

/*
 * Received buffered datagrams.
 * server - pointer to the valid datagram client.
 */
void updateStreamClient(
	StreamClient* client);

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
