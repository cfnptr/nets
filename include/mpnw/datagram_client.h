#pragma once
#include "mpnw/socket.h"

/* Datagram client instance handle (UDP) */
typedef struct DatagramClient DatagramClient;

/* Datagram client datagram receive function */
typedef void(*OnDatagramClientReceive)(
	DatagramClient* client,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Creates a new datagram client (UDP).
 * Returns datagram client on success, otherwise NULL.
 *
 * remoteAddress - pointer to the valid server address.
 * bufferSize - socket datagram receive buffer size.
 * onReceive - pointer to the valid receive function.
 * handle - pointer to the receive function argument.
 */
DatagramClient* createDatagramClient(
	const SocketAddress* remoteAddress,
	size_t bufferSize,
	OnDatagramClientReceive onReceive,
	void* handle);

/*
 * Destroys specified datagram client.
 * client - pointer to the datagram client or NULL.
 */
void destroyDatagramClient(DatagramClient* client);

/*
 * Returns datagram client receive buffer size.
 * client - pointer to the valid datagram client.
 */
size_t getDatagramClientBufferSize(
	const DatagramClient* client);

/*
 * Returns datagram client receive function.
 * client - pointer to the valid datagram client.
 */
OnDatagramClientReceive getDatagramClientOnReceive(
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
 * Receive buffered datagrams.
 * Returns true if datagram received.
 *
 * client - pointer to the valid datagram client.
 */
bool updateDatagramClient(
	DatagramClient* client);

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
