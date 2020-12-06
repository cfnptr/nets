#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <string.h>

struct StreamClient
{
	struct SocketAddress* remoteAddress;
	StreamClientReceive* receiveFunctions;
	size_t receiveFunctionCount;
	void* functionArgument;
	size_t receiveBufferSize;
	uint8_t* receiveBuffer;
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
	enum AddressFamily addressFamily,
	const struct SocketAddress* _remoteAddress,
	const StreamClientReceive* _receiveFunctions,
	size_t receiveFunctionCount,
	void* functionArgument,
	size_t receiveBufferSize)
{
	if (_receiveFunctions == NULL ||
		receiveFunctionCount == 0 ||
		receiveFunctionCount > 256 ||
		receiveBufferSize == 0)
	{
		return NULL;
	}

	struct StreamClient* client =
		malloc(sizeof(struct StreamClient));
	struct SocketAddress* remoteAddress =
		copySocketAddress(_remoteAddress);
	size_t receiveFunctionSize =
		receiveFunctionCount * sizeof(StreamClientReceive);
	StreamClientReceive* receiveFunctions = malloc(
		receiveFunctionSize);
	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	struct SocketAddress* localAddress = NULL;

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

	struct Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
		addressFamily);

	bool result = bindSocket(
		receiveSocket,
		localAddress);

	if (client == NULL ||
		remoteAddress == NULL ||
		receiveFunctions == NULL ||
		receiveBuffer == NULL ||
		localAddress == NULL ||
		receiveSocket == NULL ||
		result == false)
	{
		free(client);
		destroySocketAddress(remoteAddress);
		free(receiveFunctions);
		free(receiveBuffer);
		destroySocketAddress(localAddress);
		destroySocket(receiveSocket);
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
		free(client);
		destroySocketAddress(remoteAddress);
		free(receiveFunctions);
		free(receiveBuffer);
		destroySocketAddress(localAddress);
		destroySocket(receiveSocket);
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
	const struct StreamClient* client,
	bool* running)
{
	if (client == NULL ||
		running == NULL)
	{
		return  false;
	}

	*running = client->threadRunning;
	return true;
}

bool streamClientSend(
	struct StreamClient* client,
	const void* buffer,
	size_t count)
{
	if (client == NULL)
		return false;

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
