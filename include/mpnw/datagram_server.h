#pragma once
#include "mpnw/socket.h"

/* Datagram server instance handle (UDP) */
typedef struct DatagramServer DatagramServer;

/* Datagram server datagram receive function */
typedef void(*DatagramServerReceive)(
	DatagramServer* datagramServer,
	const SocketAddress* socketAddress,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Creates a new datagram server (UDP).
 * Returns datagram server on success, otherwise NULL.
 *
 * addressFamily - local datagram socket address family.
 * port - pointer to the valid local address port string.
 * receiveBufferSize - socket datagram receive buffer size.
 * receiveFunction - pointer to the valid receive function.
 * functionArgument - pointer to the receive function argument.
 * sslContext - pointer to the SSL context or NULL.
 */
DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	const char* port,
	size_t receiveBufferSize,
	DatagramServerReceive receiveFunction,
	void* handle,
	SslContext* sslContext);

/*
 * Destroys specified datagram server.
 * server - pointer to the datagram server or NULL.
 */
void destroyDatagramServer(DatagramServer* server);

/*
 * Returns datagram server receive buffer size.
 * server - pointer to the valid datagram server.
 */
size_t getDatagramServerReceiveBufferSize(
	const DatagramServer* server);

/*
 * Returns datagram server receive function.
 * server - pointer to the valid datagram server.
 */
DatagramServerReceive getDatagramServerReceiveFunction(
	const DatagramServer* server);

/*
 * Returns datagram server handle.
 * server - pointer to the valid datagram server.
 */
void* getDatagramServerHandle(
	const DatagramServer* server);

/*
 * Returns datagram server socket.
 * server - pointer to the valid datagram server.
 */
Socket* getDatagramServerSocket(
	const DatagramServer* server);

/*
 * Returns current datagram server running state.
 * server - pointer to the valid datagram server.
 */
bool isDatagramServerRunning(
	const DatagramServer* server);

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
	DatagramServer* server,
	const void* buffer,
	size_t count,
	const SocketAddress* address);
