#include "mpnw/stream_client.h"
#include "mpmt/thread.h"

#include <time.h>
#include <assert.h>

struct StreamClient
{
	size_t receiveBufferSize;
	StreamClientReceive receiveFunction;
	void* handle;
	uint8_t* receiveBuffer;
	struct Socket* receiveSocket;
	struct Thread* receiveThread;
	volatile bool threadRunning;
};

static void streamClientReceiveHandler(
	void* argument)
{
	struct StreamClient* client =
		(struct StreamClient*)argument;
	StreamClientReceive receiveFunction =
		client->receiveFunction;
	size_t receiveBufferSize =
		client->receiveBufferSize;
	uint8_t* receiveBuffer =
		client->receiveBuffer;
	struct Socket* receiveSocket =
		client->receiveSocket;

	bool result;
	size_t byteCount;

	while (client->threadRunning == true)
	{
		result = socketReceive(
			receiveSocket,
			receiveBuffer,
			receiveBufferSize,
			&byteCount);

		if (result == false)
		{
			sleepThread(0.001);
			continue;
		}

		result = receiveFunction(
			client,
			receiveBuffer,
			byteCount);

		if (result == false)
			break;
	}

	client->threadRunning = false;
}

struct StreamClient* createStreamClient(
	uint8_t addressFamily,
	size_t receiveBufferSize,
	StreamClientReceive receiveFunction,
	void* handle,
	struct SslContext* sslContext)
{
	assert(receiveBufferSize != 0);
	assert(receiveFunction != NULL);
	assert(isNetworkInitialized() == true);

	struct StreamClient* client = malloc(
		sizeof(struct StreamClient));

	if (client == NULL)
		return NULL;

	uint8_t* receiveBuffer = malloc(
		receiveBufferSize * sizeof(uint8_t));

	if (receiveBuffer == NULL)
	{
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
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	if (localAddress == NULL)
	{
		free(receiveBuffer);
		free(client);
		return NULL;
	}

	struct Socket* receiveSocket = createSocket(
		STREAM_SOCKET_TYPE,
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
		free(client);
		return NULL;
	}

	client->receiveBufferSize = receiveBufferSize;
	client->receiveFunction = receiveFunction;
	client->handle = handle;
	client->receiveBuffer = receiveBuffer;
	client->receiveSocket = receiveSocket;
	client->threadRunning = true;

	struct Thread* receiveThread = createThread(
		streamClientReceiveHandler,
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
	assert(isNetworkInitialized() == true);

	if (client == NULL)
		return;

	client->threadRunning = false;

	joinThread(client->receiveThread);
	destroyThread(client->receiveThread);

	shutdownSocket(
		client->receiveSocket,
		SHUTDOWN_RECEIVE_SEND);
	destroySocket(client->receiveSocket);

	free(client->receiveBuffer);
	free(client);
}

size_t getStreamClientReceiveBufferSize(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->receiveBufferSize;
}

StreamClientReceive getStreamClientReceiveFunction(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->receiveFunction;
}

void* getStreamClientHandle(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->handle;
}

struct Socket* getStreamClientSocket(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->receiveSocket;
}

bool isStreamClientRunning(
	const struct StreamClient* client)
{
	assert(client != NULL);
	return client->threadRunning;
}

bool connectStreamClient(
	struct StreamClient* streamClient,
	const struct SocketAddress* address,
	double timeoutTime)
{
	assert(streamClient != NULL);
	assert(address != NULL);

	return connectSocket(
		streamClient->receiveSocket,
		address,
		timeoutTime);
}

bool streamClientSend(
	struct StreamClient* client,
	const void* buffer,
	size_t count)
{
	assert(client != NULL);
	assert(buffer != NULL);
	assert(count != 0);

	return socketSend(
		client->receiveSocket,
		buffer,
		count);
}
