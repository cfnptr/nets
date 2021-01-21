#include "mpnw/datagram_server.h"
#include "mpmt/thread.h"

#include <string.h>
#include <assert.h>

struct DatagramServer
{
	DatagramServerReceive receiveFunction;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

static void datagramServerReceiveHandler(
	void* argument)
{
	struct DatagramServer* server =
		(struct DatagramServer*)argument;
	DatagramServerReceive receiveFunction =
		server->receiveFunction;
	void* functionArgument =
		server->functionArgument;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	uint8_t* receiveBuffer =
		server->receiveBuffer;
	struct Socket* receiveSocket =
		server->receiveSocket;

	bool result;
	size_t byteCount;
	struct SocketAddress* remoteAddress;

	while (server->threadRunning == true)
	{
		result = socketReceiveFrom(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&remoteAddress,
			&byteCount);

		if (result == false || byteCount == 0)
		{
			sleepThread(1);
			continue;
		}

		receiveFunction(
			server,
			remoteAddress,
			receiveBuffer,
			byteCount,
			functionArgument);

		destroySocketAddress(
			remoteAddress);
	}
}

struct DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	struct SslContext* sslContext,
	const char* port,
	DatagramServerReceive receiveFunction,
	void* functionArgument,
	size_t receiveBufferSize)
{
	assert(port != NULL);
	assert(receiveFunction != NULL);
	assert(receiveBufferSize != 0);

	struct DatagramServer* server = malloc(
		sizeof(struct DatagramServer));

	if (server == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		sslContext);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	struct SocketAddress* localAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			port);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			port);
	}
	else
	{
		abort();
	}

	if (localAddress == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	bool result = bindSocket(
		receiveSocket,
		localAddress);

	destroySocketAddress(
		localAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveFunction = receiveFunction;
	server->functionArgument = functionArgument;
	server->receiveBufferSize = receiveBufferSize;
	server->receiveBuffer = receiveBuffer;
	server->threadRunning = true;
	server->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		datagramServerReceiveHandler,
		server);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveThread = receiveThread;
	return server;
}

void destroyDatagramServer(
	struct DatagramServer* server)
{
	if (server == NULL)
		return;

	server->threadRunning = false;

	destroySocket(server->receiveSocket);
	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);

	free(server->receiveBuffer);
	free(server);
}

bool datagramServerSend(
	struct DatagramServer* server,
	const void* buffer,
	size_t count,
	const struct SocketAddress* address)
{
	assert(server != NULL);
	assert(buffer != NULL);
	assert(count != 0);
	assert(address != NULL);

	return socketSendTo(
		server->receiveSocket,
		buffer,
		count,
		address);
}
