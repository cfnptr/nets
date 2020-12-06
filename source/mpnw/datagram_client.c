#include "mpnw/datagram_client.h"
#include "mpmt/thread.h"

#include <assert.h>

struct DatagramClient
{
	DatagramClientReceive* receiveFunctions;
	size_t receiveFunctionCount;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

void datagramClientReceive(void* argument)
{
	assert(argument != NULL);

	struct DatagramClient* client =
		(struct DatagramClient*)argument;
	DatagramClientReceive* receiveFunctions =
		client->receiveFunctions;
	size_t receiveFunctionCount =
		client->receiveFunctionCount;
	void* functionArgument =
		client->functionArgument;
	size_t receiveBufferSize =
		client->receiveBufferSize;
	uint8_t* receiveBuffer =
		client->receiveBuffer;
	struct Socket* receiveSocket =
		client->receiveSocket;

	size_t byteCount;

	while (true)
	{
		bool result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false || byteCount == 0)
		{
			client->threadRunning = false;
			return;
		}

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			DatagramClientReceive receiveFunction =
				receiveFunctions[functionIndex];

			receiveFunction(
				receiveBuffer,
				byteCount,
				functionArgument);
		}
	}
}

struct DatagramClient* createDatagramClient(
	const struct SocketAddress* localAddress,
	const struct SocketAddress* remoteAddress,
	DatagramClientReceive* receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize)
{
	assert(localAddress != NULL);
	assert(receiveFunctions != NULL);
	assert(receiveFunctionCount > 0);
	assert(receiveFunctionCount <= 256);
	assert(receiveBufferSize > 0);

	struct DatagramClient* client =
		malloc(sizeof(struct DatagramClient));

	if (client == NULL)
		return NULL;

	client->receiveFunctions = receiveFunctions;
	client->receiveFunctionCount = receiveFunctionCount;
	client->functionArgument = functionArgument;
	client->receiveFunctionCount = receiveFunctionCount;
	client->receiveBufferSize = receiveBufferSize;

	client->threadRunning = true;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(client);
		return NULL;
	}

	client->receiveBuffer = receiveBuffer;

	enum AddressFamily addressFamily;

	bool result = getSocketAddressFamily(
		localAddress,
		&addressFamily);

	if (result == false)
	{
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		DATAGRAM_SOCKET_TYPE,
		addressFamily);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	result = bindSocket(
		receiveSocket,
		localAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	result = connectSocket(
		receiveSocket,
		remoteAddress);

	if (result == false)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	client->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		datagramClientReceive,
		client);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	client->receiveThread = receiveThread;
	return client;
}

void destroyDatagramClient(
	struct DatagramClient* client)
{
	if (client == NULL)
		return;

	destroySocket(client->receiveSocket);
	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);

	free(client->receiveBuffer);
	free(client);
}

bool isDatagramClientRunning(
	struct DatagramClient* client)
{
	assert(client != NULL);
	return client->threadRunning;
}

bool datagramClientSend(
	struct DatagramClient* client,
	const void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
