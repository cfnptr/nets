#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle (TCP) */
typedef struct StreamClient* StreamClient;

/* Stream client receive function */
typedef void(*OnStreamClientReceive)(
	StreamClient client,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Create a new stream client instance (TCP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * bufferSize - message receive buffer size.
 * onReceive - message receive function.
 * handle - receive function argument.
 * sslContext - SSL context instance or NULL.
 * streamClient - pointer to the streamClient value.
 */
MpnwResult createStreamClient(
	AddressFamily addressFamily,
	size_t bufferSize,
	OnStreamClientReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamClient* streamClient);

/*
 * Destroy stream client instance.
 * client - stream client instance or NULL.
 */
void destroyStreamClient(StreamClient client);

/*
* Returns stream client receive buffer size.
* client - stream client instance.
*/
size_t getStreamClientBufferSize(StreamClient client);

/*
* Returns stream client receive function.
* client - stream client instance.
*/
OnStreamClientReceive getStreamClientOnReceive(StreamClient client);

/*
 * Returns stream client handle.
 * client - stream client instance.
 */
void* getStreamClientHandle(StreamClient client);

/*
 * Returns stream client socket.
 * client - stream client instance.
 */
Socket getStreamClientSocket(StreamClient client);

/*
 * Connect stream client to the server.
 * Returns true on success.
 *
 * socket - stream client instance.
 * address - remote socket address.
 * timeoutTime - time out time (ms).
 */
bool connectStreamClient(
	StreamClient client,
	SocketAddress address,
	double timeout);

/*
 * Receive buffered datagrams.
 * Returns true if message received.
 *
 * client - stream client instance.
 */
bool updateStreamClient(StreamClient client);

/*
 * Send message to the stream server.
 * Returns true on success.
 *
 * client - stream client instance.
 * buffer - message send buffer.
 * count - send byte count.
 */
bool streamClientSend(
	StreamClient client,
	const void* buffer,
	size_t count);
