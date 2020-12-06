#include "mpnw/datagram_server.h"
#include "mpmt/thread.h"

#include <assert.h>

struct DatagramServer
{
	DatagramServerReceive* receiveFunctions;
	size_t receiveFunctionCount;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

void datagramServerReceive(void* argument)
{
	assert(argument != NULL);

	struct DatagramServer* server =
		(struct DatagramServer*)argument;
	DatagramServerReceive* receiveFunctions =
		server->receiveFunctions;
	size_t receiveFunctionCount =
		server->receiveFunctionCount;
	void* functionArgument =
		server->functionArgument;
	size_t receiveBufferSize =
		server->receiveBufferSize;
	uint8_t* receiveBuffer =
		server->receiveBuffer;
	struct Socket* receiveSocket =
		server->receiveSocket;

	size_t byteCount;
	struct SocketAddress* remoteAddress;

	while (server->threadRunning == true)
	{
		bool result = socketReceiveFrom(
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

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			DatagramServerReceive receiveFunction =
				receiveFunctions[functionIndex];

			receiveFunction(
				remoteAddress,
				receiveBuffer,
				byteCount,
				functionArgument);
		}

		destroySocketAddress(
			remoteAddress);
	}
}

struct DatagramServer* createDatagramServer(
	const struct SocketAddress* localAddress,
	DatagramServerReceive* receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize)
{
	assert(localAddress != NULL);
	assert(receiveFunctions != NULL);
	assert(receiveFunctionCount > 0);
	assert(receiveFunctionCount <= 256);
	assert(receiveBufferSize > 0);

	struct DatagramServer* server =
		malloc(sizeof(struct DatagramServer));

	if (server == NULL)
		return NULL;

	server->receiveFunctions = receiveFunctions;
	server->receiveFunctionCount = receiveFunctionCount;
	server->functionArgument = functionArgument;
	server->receiveFunctionCount = receiveFunctionCount;
	server->receiveBufferSize = receiveBufferSize;

	server->threadRunning = true;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(server);
		return NULL;
	}

	server->receiveBuffer = receiveBuffer;

	enum AddressFamily addressFamily;

	bool result = getSocketAddressFamily(
		localAddress,
		&addressFamily);

	if (result == false)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	result = bindSocket(
		receiveSocket,
		localAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(server);
		return NULL;
	}

	server->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		datagramServerReceive,
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
