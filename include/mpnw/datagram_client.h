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
 * Returns datagram client on success, otherwise null.
 *
 * addressFamily - local datagram socket address family.
 * remoteAddress - pointer to the valid server address.
 * receiveFunctions - pointer to the valid receive functions.
 * receiveFunctionCount - receive function array item count.
 * stopFunction - pointer to the valid stop function.
 * functionArgument - pointer to the server function argument.
 * receiveBufferSize - socket datagram receive buffer size.
 */
struct DatagramClient* createDatagramClient(
	enum AddressFamily addressFamily,
	const struct SocketAddress* remoteAddress,
	const DatagramClientReceive* receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize);

/*
 * Destroys specified datagram client.
 * client - pointer to the valid datagram client.
 */
void destroyDatagramClient(
	struct DatagramClient* client);

/*
 * Gets current datagram client running state
 * Returns true on successful get.
 *
 * client - pointer to the valid datagram client.
 * running - pointer to the valid running value.
 */
bool getDatagramClientRunning(
	const struct DatagramClient* client,
	bool* running);

/*
 * Sends datagram to the server.
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
