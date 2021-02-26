#pragma once
#include "mpnw/socket.h"

/* Datagram client instance handle */
struct DatagramClient;

/* Datagram client datagram receive function */
typedef bool(*DatagramClientReceive)(
	struct DatagramClient* client,
	const uint8_t* buffer,
	size_t count);

/*
 * Creates a new datagram client.
 * Returns datagram client on success, otherwise NULL.
 *
 * remoteAddress - pointer to the valid server address.
 * receiveBufferSize - socket datagram receive buffer size.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
struct DatagramClient* createDatagramClient(
	const struct SocketAddress* remoteAddress,
	size_t receiveBufferSize,
	DatagramClientReceive receiveFunction,
	void* functionArgument,
	struct SslContext* sslContext);

/*
 * Destroys specified datagram client.
 * client - pointer to the datagram client or NULL.
 */
void destroyDatagramClient(
	struct DatagramClient* client);

/*
 * Returns datagram client receive buffer size.
 * client - pointer to the valid datagram client.
 */
size_t getDatagramClientReceiveBufferSize(
	const struct DatagramClient* client);

/*
 * Returns datagram client receive function argument.
 * client - pointer to the valid datagram client.
 */
void* getDatagramClientFunctionArgument(
	const struct DatagramClient* client);

/*
 * Returns datagram client socket.
 * client - pointer to the valid datagram client.
 */
const struct Socket* getDatagramClientSocket(
	const struct DatagramClient* client);

/*
 * Returns current datagram client running state.
 * client - pointer to the valid datagram client.
 */
bool isDatagramClientRunning(
	const struct DatagramClient* client);

/*
 * Sends message to the datagram server.
 * Returns true on success.
 *
 * client - pointer to the valid datagram client.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 */
bool datagramClientSend(
	struct DatagramClient* client,
	const void* buffer,
	size_t count);
