#pragma once
#include "mpnw/socket.h"

/* Datagram client instance handle (UDP) */
typedef struct DatagramClient DatagramClient;

/* Datagram client datagram receive function */
typedef void(*DatagramClientReceive)(
	DatagramClient* datagramClient,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Creates a new datagram client (UDP).
 * Returns datagram client on success, otherwise NULL.
 *
 * remoteAddress - pointer to the valid server address.
 * receiveBufferSize - socket datagram receive buffer size.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
DatagramClient* createDatagramClient(
	const SocketAddress* remoteAddress,
	size_t receiveBufferSize,
	DatagramClientReceive receiveFunction,
	void* handle,
	SslContext* sslContext);

/*
 * Destroys specified datagram client.
 * client - pointer to the datagram client or NULL.
 */
void destroyDatagramClient(
	DatagramClient* client);

/*
 * Returns datagram client receive buffer size.
 * client - pointer to the valid datagram client.
 */
size_t getDatagramClientReceiveBufferSize(
	const DatagramClient* client);

/*
 * Returns datagram client receive function.
 * client - pointer to the valid datagram client.
 */
DatagramClientReceive getDatagramClientReceiveFunction(
	const DatagramClient* client);

/*
 * Returns datagram client handle.
 * client - pointer to the valid datagram client.
 */
void* getDatagramClientHandle(
	const DatagramClient* client);

/*
 * Returns datagram client socket.
 * client - pointer to the valid datagram client.
 */
Socket* getDatagramClientSocket(
	const DatagramClient* client);

/*
 * Returns current datagram client running state.
 * client - pointer to the valid datagram client.
 */
bool isDatagramClientRunning(
	const DatagramClient* client);

/*
 * Sends message to the datagram server.
 * Returns true on success.
 *
 * client - pointer to the valid datagram client.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool datagramClientSend(
	DatagramClient* client,
	const void* buffer,
	size_t count);
