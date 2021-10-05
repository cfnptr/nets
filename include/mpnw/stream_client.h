#pragma once
#include "mpnw/socket.h"

/* Stream client instance handle (TCP) */
typedef struct StreamClient* StreamClient;

/* Stream client receive function */
typedef void(*OnStreamClientReceive)(
	StreamClient streamClient,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Create a new stream client instance (TCP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * receiveBufferSize - message receive buffer size.
 * onReceive - message receive function.
 * handle - receive function argument.
 * sslContext - SSL context instance or NULL.
 * streamClient - pointer to the streamClient value.
 */
MpnwResult createStreamClient(
	AddressFamily addressFamily,
	size_t receiveBufferSize,
	OnStreamClientReceive onReceive,
	void* handle,
	SslContext sslContext,
	StreamClient* streamClient);

/*
 * Destroy stream client instance.
 * streamClient - stream client instance or NULL.
 */
void destroyStreamClient(StreamClient streamClient);

/*
* Returns stream client receive buffer size.
* streamClient - stream client instance.
*/
size_t getStreamClientReceiveBufferSize(StreamClient streamClient);

/*
* Returns stream client receive function.
* streamClient - stream client instance.
*/
OnStreamClientReceive getStreamClientOnReceive(StreamClient streamClient);

/*
 * Returns stream client handle.
 * streamClient - stream client instance.
 */
void* getStreamClientHandle(StreamClient streamClient);

/*
 * Returns stream client socket.
 * streamClient - stream client instance.
 */
Socket getStreamClientSocket(StreamClient streamClient);

/*
 * Connect stream client to the server.
 * Returns true on success.
 *
 * streamClient - stream client instance.
 * socketAddress - remote socket address.
 * timeoutTime - time out time (ms).
 */
bool connectStreamClient(
	StreamClient streamClient,
	SocketAddress socketAddress,
	double timeoutTime);

/*
 * Receive buffered datagrams.
 * Returns true if message received.
 *
 * streamClient - stream client instance.
 */
bool updateStreamClient(StreamClient streamClient);

/*
 * Send message to the stream server.
 * Returns true on success.
 *
 * streamClient - stream client instance.
 * sendBuffer - message send buffer.
 * byteCount - send byte count.
 */
bool streamClientSend(
	StreamClient streamClient,
	const void* sendBuffer,
	size_t byteCount);
