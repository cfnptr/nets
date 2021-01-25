#include "mpnw/datagram_server.h"
#include "mpmt/thread.h"

#include <string.h>
#include <assert.h>

struct DatagramServer
{
	size_t receiveBufferSize;
	DatagramServerReceive receiveFunction;
	void* functionArgument;
	uint8_t* receiveBuffer;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
	volatile bool threadRunning;
};

void datagramServerReceiveHandler(
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

	struct SocketAddress* remoteAddress = createSocketAddress(
		ANY_IP_ADDRESS_V4,
		ANY_IP_ADDRESS_PORT);

	if (remoteAddress == NULL)
		return;

	while (server->threadRunning == true)
	{
		result = socketReceiveFrom(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			remoteAddress,
			&byteCount);

		if (result == false || byteCount == 0)
		{
			sleepThread(1);
			continue;
		}

		result = receiveFunction(
			server,
			remoteAddress,
			receiveBuffer,
			byteCount,
			functionArgument);

		if (result == false)
			break;
	}

	server->threadRunning = false;
}

struct DatagramServer* createDatagramServer(
	uint8_t addressFamily,
	const char* port,
	size_t receiveBufferSize,
	DatagramServerReceive receiveFunction,
	void* functionArgument,
	struct SslContext* sslContext)
{
	assert(port != NULL);
	assert(receiveBufferSize != 0);
	assert(receiveFunction != NULL);

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
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily,
		localAddress,
		false,
		false,
		sslContext);

	destroySocketAddress(
		localAddress);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveBufferSize = receiveBufferSize;
	server->receiveFunction = receiveFunction;
	server->functionArgument = functionArgument;
	server->receiveBuffer = receiveBuffer;
	server->receiveSocket = receiveSocket;
	server->threadRunning = true;

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

	joinThread(server->receiveThread);
	destroyThread(server->receiveThread);
	destroySocket(server->receiveSocket);

	free(server->receiveBuffer);
	free(server);
}

size_t getDatagramServerReceiveBufferSize(
	const struct DatagramServer* server)
{
	assert(server != NULL);
	return server->receiveBufferSize;
}

DatagramServerReceive getDatagramServerReceiveFunction(
	const struct DatagramServer* server)
{
	assert(server != NULL);
	return server->receiveFunction;
}

void* getDatagramServerFunctionArgument(
	const struct DatagramServer* server)
{
	assert(server != NULL);
	return server->functionArgument;
}

const struct Socket* getDatagramServerSocket(
	const struct DatagramServer* server)
{
	assert(server != NULL);
	return server->receiveSocket;
}

bool isDatagramServerRunning(
	const struct DatagramServer* server)
{
	assert(server != NULL);
	return server->threadRunning;
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
