#pragma once
#include "mpnw/socket.h"

/* Datagram client instance handle */
struct DatagramClient;

/* Datagram client datagram receive function */
typedef bool(*DatagramClientReceive)(
	struct DatagramClient* client,
	const uint8_t* buffer,
	size_t count,
	void* argument);

/*
 * Creates a new datagram client.
 * Returns datagram client on success, otherwise NULL.
 *
 * addressFamily - local datagram socket address family.
 * remoteAddress - pointer to the valid server address.
 * receiveFunction - pointer to the valid receive function.
 * stopFunction - pointer to the valid stop function.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket datagram receive buffer size.
 * sslContext - pointer to the SSL context or NULL.
 */
struct DatagramClient* createDatagramClient(
	const struct SocketAddress* remoteAddress,
	DatagramClientReceive receiveFunction,
	void* functionArgument,
	size_t receiveBufferSize,
	struct SslContext* sslContext);

/*
 * Destroys specified datagram client.
 * client - pointer to the datagram client or NULL.
 */
void destroyDatagramClient(
	struct DatagramClient* client);

/*
 * Returns current datagram client running state.
 * client - pointer to the valid datagram client.
 */
bool isDatagramClientRunning(
	const struct DatagramClient* client);

/*
 * Returns datagram client socket.
 * client - pointer to the valid datagram client.
 */
const struct Socket* getDatagramClientSocket(
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
