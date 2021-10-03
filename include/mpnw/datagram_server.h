#pragma once
#include "mpnw/socket.h"

/* Datagram server instance handle (UDP) */
typedef struct DatagramServer* DatagramServer;

/* Datagram server receive function */
typedef void(*OnDatagramServerReceive)(
	DatagramServer server,
	SocketAddress address,
	const uint8_t* buffer,
	size_t byteCount);

/*
 * Creates a new datagram server (UDP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * service - local address service string.
 * bufferSize - datagram receive buffer size.
 * onReceive - datagram receive function.
 * handle - receive function argument.
 */
MpnwResult createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t bufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* datagramServer);

/*
 * Destroy datagram server instance.
 * server - datagram server instance or NULL.
 */
void destroyDatagramServer(DatagramServer server);

/*
 * Returns datagram server receive buffer size.
 * server - datagram server instance.
 */
size_t getDatagramServerBufferSize(DatagramServer server);

/*
 * Returns datagram server receive function.
 * server - datagram server instance.
 */
OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer server);

/*
 * Returns datagram server handle.
 * server - datagram server instance.
 */
void* getDatagramServerHandle(DatagramServer server);

/*
 * Returns datagram server socket.
 * server - datagram server instance.
 */
Socket getDatagramServerSocket(DatagramServer server);

/*
 * Receive buffered datagrams.
 * Returns true if datagram received.
 *
 * server - datagram server instance.
 */
bool updateDatagramServer(DatagramServer server);

/*
 * Send message to the specified address.
 * Returns true on success.
 *
 * server - datagram server instance.
 * buffer - datagram send buffer.
 * count - send byte count.
 * address - destination socket address.
 */
bool datagramServerSend(
	DatagramServer server,
	const void* buffer,
	size_t count,
	SocketAddress address);
