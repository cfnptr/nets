#pragma once
#include "mpnw/socket.h"

/* Datagram server instance handle (UDP) */
typedef struct DatagramServer DatagramServer;

/* Datagram server datagram receive function */
typedef void(*OnDatagramServerReceive)(
	DatagramServer* server,
	const SocketAddress* address,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Creates a new datagram server (UDP).
 * Returns datagram server on success, otherwise NULL.
 *
 * addressFamily - local datagram socket address family.
 * port - pointer to the valid local address port string.
 * bufferSize - socket datagram receive buffer size.
 * onReceive - pointer to the valid receive function.
 * handle - pointer to the receive function argument.
 */
DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t bufferSize,
	OnDatagramServerReceive onReceive,
	void* handle);

/*
 * Destroys specified datagram server.
 * server - pointer to the datagram server or NULL.
 */
void destroyDatagramServer(DatagramServer* server);

/*
 * Returns datagram server receive buffer size.
 * server - pointer to the valid datagram server.
 */
size_t getDatagramServerBufferSize(
	const DatagramServer* server);

/*
 * Returns datagram server receive function.
 * server - pointer to the valid datagram server.
 */
OnDatagramServerReceive getDatagramServerOnReceive(
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
 * Receive buffered datagrams.
 * Returns true if datagram received.
 *
 * server - pointer to the valid datagram server.
 */
bool updateDatagramServer(
	DatagramServer* server);

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
