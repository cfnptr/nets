#pragma once
#include "mpnw/socket.h"

/* Datagram client instance handle (UDP) */
typedef struct DatagramClient* DatagramClient;

/* Datagram client receive function */
typedef void(*OnDatagramClientReceive)(
	DatagramClient client,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Create a new datagram client instance (UDP).
 * Returns operation MPNW result.
 *
 * remoteAddress - remote socket address.
 * bufferSize - datagram receive buffer size.
 * onReceive - datagram receive function.
 * handle - receive function argument.
 * datagramClient - pointer to the datagramClient value.
 */
MpnwResult createDatagramClient(
	SocketAddress remoteAddress,
	size_t bufferSize,
	OnDatagramClientReceive onReceive,
	void* handle,
	DatagramClient* datagramClient);

/*
 * Destroy datagram client instance.
 * client - datagram client instance or NULL.
 */
void destroyDatagramClient(DatagramClient client);

/*
 * Returns datagram client receive buffer size.
 * client - datagram client instance.
 */
size_t getDatagramClientBufferSize(DatagramClient client);

/*
 * Returns datagram client receive function.
 * client - datagram client instance.
 */
OnDatagramClientReceive getDatagramClientOnReceive(DatagramClient client);

/*
 * Returns datagram client handle.
 * client - datagram client instance.
 */
void* getDatagramClientHandle(DatagramClient client);

/*
 * Returns datagram client socket.
 * client - datagram client instance.
 */
Socket getDatagramClientSocket(DatagramClient client);

/*
 * Receive buffered datagrams.
 * Returns true if datagram received.
 *
 * client - datagram client instance.
 */
bool updateDatagramClient(DatagramClient client);

/*
 * Send message to the datagram server.
 * Returns true on success.
 *
 * client - datagram client instance.
 * buffer - datagram send buffer.
 * count - send byte count.
 */
bool datagramClientSend(
	DatagramClient client,
	const void* buffer,
	size_t count);
