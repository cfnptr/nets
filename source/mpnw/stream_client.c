#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <assert.h>

struct StreamClient
{
	struct SocketAddress* remoteAddress;
	StreamClientReceive* receiveFunctions;
	size_t receiveFunctionCount;
	StreamClientStop stopFunction;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	struct Socket* receiveSocket;
	volatile enum StreamClientState state;
	struct Thread* receiveThread;
};

void streamClientReceive(void* argument)
{
	assert(argument != NULL);

	struct StreamClient* client =
		(struct StreamClient*)argument;
	struct SocketAddress* remoteAddress =
		client->remoteAddress;
	StreamClientReceive* receiveFunctions =
		client->receiveFunctions;
	size_t receiveFunctionCount =
		client->receiveFunctionCount;
	StreamClientStop stopFunction =
		client->stopFunction;
	void* functionArgument =
		client->functionArgument;
	size_t receiveBufferSize =
		client->receiveBufferSize;
	uint8_t* receiveBuffer =
		client->receiveBuffer;
	struct Socket* receiveSocket =
		client->receiveSocket;

	bool result = connectSocket(
		receiveSocket,
		remoteAddress);

	if (result == false)
	{
		client->state =
			NOT_CONNECTED_STREAM_CLIENT;
		return;
	}

	client->state = CONNECTED_STREAM_CLIENT;

	size_t byteCount;

	while (true)
	{
		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false ||
			byteCount == 0)
		{
			stopFunction(
				functionArgument);
			return;
		}

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			StreamClientReceive receiveFunction =
				receiveFunctions[functionIndex];

			receiveFunction(
				receiveBuffer,
				byteCount,
				functionArgument);
		}
	}
}

struct StreamClient* createStreamClient(
	const struct SocketAddress* localAddress,
	const struct SocketAddress* remoteAddress,
	StreamClientReceive* receiveFunctions,
	size_t receiveFunctionCount,
	StreamClientStop stopFunction,
	void* functionArgument,
	size_t receiveBufferSize)
{
	assert(localAddress != NULL);
	assert(receiveFunctions != NULL);
	assert(receiveFunctionCount > 0);
	assert(receiveFunctionCount <= 256);
	assert(receiveBufferSize > 0);

	struct StreamClient* client =
		malloc(sizeof(struct StreamClient));

	if (client == NULL)
		return NULL;

	struct SocketAddress* _remoteAddress =
		copySocketAddress(remoteAddress);

	if (_remoteAddress == NULL)
	{
		free(client);
		return NULL;
	}

	client->remoteAddress = _remoteAddress;
	client->receiveFunctions = receiveFunctions;
	client->receiveFunctionCount = receiveFunctionCount;
	client->functionArgument = functionArgument;
	client->receiveFunctionCount = receiveFunctionCount;
	client->stopFunction = stopFunction;
	client->receiveBufferSize = receiveBufferSize;

	client->state = CONNECTING_STREAM_CLIENT;

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
		STREAM_SOCKET_TYPE,
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

	client->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		streamClientReceive,
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

void destroyStreamClient(
	struct StreamClient* client)
{
	if (client == NULL)
		return;

	destroySocket(client->receiveSocket);
	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);

	destroySocketAddress(
		client->remoteAddress);

	free(client->receiveBuffer);
	free(client);
}

enum StreamClientState getStreamClientState(
	struct StreamClient* client)
{
	assert(client != NULL);
	return client->state;
}

bool streamClientSend(
	struct StreamClient* client,
	const void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);

	if (client->state != CONNECTED_STREAM_CLIENT)
		return false;

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
