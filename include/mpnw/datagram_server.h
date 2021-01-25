#pragma once
#include "mpnw/socket.h"

/* Datagram server instance handle */
struct DatagramServer;

/* Datagram server datagram receive function */
typedef bool(*DatagramServerReceive)(
	struct DatagramServer* server,
	const struct SocketAddress* address,
	const uint8_t* buffer,
	size_t count,
	void* argument);

/*
 * Creates a new datagram server.
 * Returns datagram server on success, otherwise NULL.
 *
 * addressFamily - local datagram socket address family.
 * port - pointer to the valid local address port string.
 * receiveBufferSize - socket datagram receive buffer size.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
struct DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	const char* port,
	size_t receiveBufferSize,
	DatagramServerReceive receiveFunction,
	void* functionArgument,
	struct SslContext* sslContext);

/*
 * Destroys specified datagram server.
 * server - pointer to the datagram server or NULL.
 */
void destroyDatagramServer(
	struct DatagramServer* server);

/*
 * Returns datagram server receive buffer size.
 * server - pointer to the valid datagram server.
 */
size_t getDatagramServerReceiveBufferSize(
	const struct DatagramServer* server);

/*
* Returns datagram server receive function.
* server - pointer to the valid datagram server.
*/
DatagramServerReceive getDatagramServerReceiveFunction(
	const struct DatagramServer* server);

/*
 * Returns datagram server receive function argument.
 * server - pointer to the valid datagram server.
 */
void* getDatagramServerFunctionArgument(
	const struct DatagramServer* server);

/*
 * Returns datagram server socket.
 * server - pointer to the valid datagram server.
 */
const struct Socket* getDatagramServerSocket(
	const struct DatagramServer* server);

/*
 * Returns current datagram server running state.
 * server - pointer to the valid datagram server.
 */
bool isDatagramServerRunning(
	const struct DatagramServer* server);

/*
 * Sends message to the specified address.
 * Returns true on success.
 *
 * server - pointer to the valid datagram server.
 * buffer - pointer to the valid data buffer.
 * count - data buffer send byte count.
 * address - destination datagram address.
 */
bool datagramServerSend(
	struct DatagramServer* server,
	const void* buffer,
	size_t count,
	const struct SocketAddress* address);
