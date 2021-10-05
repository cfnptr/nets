#pragma once
#include "mpnw/socket.h"

/* Datagram server instance handle (UDP) */
typedef struct DatagramServer* DatagramServer;

/* Datagram server receive function */
typedef void(*OnDatagramServerReceive)(
	DatagramServer datagramServer,
	SocketAddress socketAddress,
	const uint8_t* receiveBuffer,
	size_t byteCount);

/*
 * Creates a new datagram server (UDP).
 * Returns operation MPNW result.
 *
 * addressFamily - local socket address family.
 * service - local address service string.
 * receiveBufferSize - datagram receive buffer size.
 * onReceive - datagram receive function.
 * handle - receive function argument.
 */
MpnwResult createDatagramServer(
	uint8_t addressFamily,
	const char* service,
	size_t receiveBufferSize,
	OnDatagramServerReceive onReceive,
	void* handle,
	DatagramServer* datagramServer);

/*
 * Destroy datagram server instance.
 * datagramServer - datagram server instance or NULL.
 */
void destroyDatagramServer(DatagramServer datagramServer);

/*
 * Returns datagram server receive buffer size.
 * datagramServer - datagram server instance.
 */
size_t getDatagramServerReceiveBufferSize(DatagramServer datagramServer);

/*
 * Returns datagram server receive function.
 * datagramServer - datagram server instance.
 */
OnDatagramServerReceive getDatagramServerOnReceive(DatagramServer datagramServer);

/*
 * Returns datagram server handle.
 * datagramServer - datagram server instance.
 */
void* getDatagramServerHandle(DatagramServer datagramServer);

/*
 * Returns datagram server socket.
 * datagramServer - datagram server instance.
 */
Socket getDatagramServerSocket(DatagramServer datagramServer);

/*
 * Receive buffered datagrams.
 * Returns true if datagram received.
 *
 * datagramServer - datagram server instance.
 */
bool updateDatagramServer(DatagramServer datagramServer);

/*
 * Send message to the specified address.
 * Returns true on success.
 *
 * datagramServer - datagram server instance.
 * sendBuffer - datagram send buffer.
 * byteCount - send byte count.
 * socketAddress - destination socket address.
 */
bool datagramServerSend(
	DatagramServer datagramServer,
	const void* sendBuffer,
	size_t byteCount,
	SocketAddress socketAddress);
