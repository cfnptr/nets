#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <string.h>
#include <assert.h>

struct StreamClient
{
	StreamClientReceive* receiveFunctions;
	size_t receiveFunctionCount;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
	struct SocketAddress* remoteAddress;
	volatile bool threadRunning;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
};

static void streamClientReceiveHandler(
	void* argument)
{
	struct StreamClient* client =
		(struct StreamClient*)argument;
	struct SocketAddress* remoteAddress =
		client->remoteAddress;
	StreamClientReceive* receiveFunctions =
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

	bool result = connectSocket(
		receiveSocket,
		remoteAddress);

	if (result == false)
	{
		client->threadRunning = false;
		return;
	}

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
			client->threadRunning = false;
			return;
		}

		size_t functionIndex =
			(size_t)receiveBuffer[0];

		if (functionIndex < receiveFunctionCount)
		{
			StreamClientReceive receiveFunction =
				receiveFunctions[functionIndex];

			result = receiveFunction(
				client,
				receiveBuffer,
				byteCount,
				functionArgument);

			if (result == false)
			{
				client->threadRunning = false;
				return;
			}
		}
	}
}

struct StreamClient* createStreamClient(
	uint8_t addressFamily,
	struct SslContext* sslContext,
	const struct SocketAddress* _remoteAddress,
	const StreamClientReceive* _receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize)
{
	assert(_remoteAddress != NULL);
	assert(_receiveFunctions != NULL);
	assert(receiveFunctionCount != 0);
	assert(receiveFunctionCount <= 256);
	assert(receiveBufferSize != 0);

	struct StreamClient* client = malloc(
		sizeof(struct StreamClient));

	if (client == NULL)
		return NULL;

	struct SocketAddress* remoteAddress =
		copySocketAddress(_remoteAddress);

	if (remoteAddress == NULL)
	{
		free(client);
		return NULL;
	}

	size_t receiveFunctionSize =
		receiveFunctionCount * sizeof(StreamClientReceive);
	StreamClientReceive* receiveFunctions = malloc(
		receiveFunctionSize);

	if (receiveFunctions == NULL)
	{
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
		free(receiveFunctions);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily,
		sslContext);

	if (receiveSocket == NULL)
	{
		free(receiveBuffer);
		free(receiveFunctions);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	struct SocketAddress* localAddress;

	if (addressFamily == IP_V4_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V4,
			ANY_IP_ADDRESS_PORT);
	}
	else if (addressFamily == IP_V6_ADDRESS_FAMILY)
	{
		localAddress = createSocketAddress(
			ANY_IP_ADDRESS_V6,
			ANY_IP_ADDRESS_PORT);
	}
	else
	{
		abort();
	}

	if (localAddress == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(receiveFunctions);
		destroySocketAddress(remoteAddress);
		free(client);
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
		free(receiveFunctions);
		destroySocketAddress(remoteAddress);
		free(client);
		return NULL;
	}

	memcpy(
		receiveFunctions,
		_receiveFunctions,
		receiveFunctionSize);

	client->remoteAddress = remoteAddress;
	client->receiveFunctions = receiveFunctions;
	client->receiveFunctionCount = receiveFunctionCount;
	client->functionArgument = functionArgument;
	client->receiveBufferSize = receiveBufferSize;
	client->receiveBuffer = receiveBuffer;
	client->threadRunning = true;
	client->receiveSocket = receiveSocket;

	struct Thread* receiveThread = createThread(
		streamClientReceiveHandler,
		client);

	if (receiveThread == NULL)
	{
		destroySocket(receiveSocket);
		free(receiveBuffer);
		free(receiveFunctions);
		destroySocketAddress(remoteAddress);
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

	free(client->receiveBuffer);
	destroySocketAddress(client->remoteAddress);
	free(client->receiveFunctions);
	free(client);
}

bool getStreamClientRunning(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client;
}

bool streamClientSend(
	struct StreamClient* client,
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
